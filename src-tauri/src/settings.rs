use std::{fs, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "NordDownloadManager";
const KEYRING_ACCOUNT: &str = "nordvpn-service-credentials";
/// Keyring account holding the user's gofile.io session token.
pub const GOFILE_TOKEN: &str = "gofile-account-token";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Settings {
    pub download_dir: String,
    /// NordVPN country id; `None` lets the API pick servers nearest to the user.
    pub country_id: Option<u64>,
}

pub fn load(path: &Path) -> Settings {
    fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

pub fn save(path: &Path, settings: &Settings) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(settings)?).context("Could not write settings file")
}

/// NordVPN service credentials (what the proxies accept), not the account e-mail/password.
/// Stored in Windows Credential Manager rather than on disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

fn entry_for(account: &str) -> Result<keyring::Entry> {
    Ok(keyring::Entry::new(KEYRING_SERVICE, account)?)
}

fn entry() -> Result<keyring::Entry> {
    entry_for(KEYRING_ACCOUNT)
}

pub fn load_secret(account: &str) -> Option<String> {
    entry_for(account).ok()?.get_password().ok().filter(|s| !s.trim().is_empty())
}

/// Stores `value`, or removes the secret when it's empty.
pub fn save_secret(account: &str, value: &str) -> Result<()> {
    let entry = entry_for(account)?;
    if value.trim().is_empty() {
        return match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(e.into()),
        };
    }
    entry
        .set_password(value.trim())
        .context("Could not store the token in Windows Credential Manager")
}

pub fn load_credentials() -> Option<Credentials> {
    let json = entry().ok()?.get_password().ok()?;
    serde_json::from_str(&json).ok()
}

pub fn save_credentials(credentials: &Credentials) -> Result<()> {
    entry()?
        .set_password(&serde_json::to_string(credentials)?)
        .context("Could not store credentials in Windows Credential Manager")
}

pub fn clear_credentials() -> Result<()> {
    match entry()?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
