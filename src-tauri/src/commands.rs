use std::sync::Arc;

use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_opener::OpenerExt;

use crate::{
    engine::{AddRequest, DownloadManager, DownloadView},
    nord::{self, Country},
    recommend::{self, Recommendation},
    settings::{self, Credentials, Settings},
};

type Manager<'a> = State<'a, Arc<DownloadManager>>;

fn err(e: anyhow::Error) -> String {
    format!("{e:#}")
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsView {
    settings: Settings,
    /// Service username of the signed-in account, if any.
    account: Option<String>,
    has_gofile_token: bool,
}

#[tauri::command]
pub async fn get_settings(manager: Manager<'_>) -> Result<SettingsView, String> {
    let mut account = settings::load_credentials().map(|c| c.username);
    // Earlier versions saved whatever was typed; an e-mail can never be a service username.
    if account.as_ref().is_some_and(|name| name.contains('@')) {
        let _ = settings::clear_credentials();
        account = None;
    }
    let has_gofile_token = settings::load_secret(settings::GOFILE_TOKEN).is_some();
    Ok(SettingsView { settings: manager.settings(), account, has_gofile_token })
}

#[tauri::command]
pub async fn save_settings(manager: Manager<'_>, settings: Settings) -> Result<(), String> {
    manager.save_settings(settings).map_err(err)
}

/// Signs in with a Nord Account access token: fetches the service credentials, verifies and stores them.
#[tauri::command]
pub async fn sign_in_with_token(manager: Manager<'_>, token: String) -> Result<String, String> {
    if token.trim().is_empty() {
        return Err("Paste your access token first".into());
    }
    let credentials = nord::credentials_from_token(manager.api(), &token).await.map_err(err)?;
    nord::verify_credentials(manager.api(), &credentials).await.map_err(err)?;
    settings::save_credentials(&credentials).map_err(err)?;
    Ok(credentials.username)
}

/// Signs in with service credentials typed by the user, verifying them before they're stored.
#[tauri::command]
pub async fn sign_in(manager: Manager<'_>, username: String, password: String) -> Result<String, String> {
    let credentials = Credentials { username: username.trim().into(), password: password.trim().into() };
    if credentials.username.is_empty() || credentials.password.is_empty() {
        return Err("Enter both the username and password".into());
    }
    nord::verify_credentials(manager.api(), &credentials).await.map_err(err)?;
    settings::save_credentials(&credentials).map_err(err)?;
    Ok(credentials.username)
}

#[tauri::command]
pub async fn sign_out() -> Result<(), String> {
    settings::clear_credentials().map_err(err)
}

#[tauri::command]
pub async fn save_gofile_token(token: String) -> Result<(), String> {
    settings::save_secret(settings::GOFILE_TOKEN, &token).map_err(err)
}

#[tauri::command]
pub fn open_nord_account(app: AppHandle) -> Result<(), String> {
    app.opener()
        .open_url(nord::ACCOUNT_URL, None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn list_countries(manager: Manager<'_>) -> Result<Vec<Country>, String> {
    nord::countries(manager.api()).await.map_err(err)
}

#[tauri::command]
pub async fn system_recommendation(manager: Manager<'_>) -> Result<Recommendation, String> {
    Ok(recommend::recommend(None, true, manager.active_count()))
}

#[tauri::command]
pub async fn add_download(manager: Manager<'_>, request: AddRequest) -> Result<DownloadView, String> {
    manager.inner().add(request).map_err(err)
}

#[tauri::command]
pub async fn list_downloads(manager: Manager<'_>) -> Result<Vec<DownloadView>, String> {
    Ok(manager.list())
}

#[tauri::command]
pub async fn pause_download(manager: Manager<'_>, id: String) -> Result<(), String> {
    manager.pause(&id).await.map_err(err)
}

#[tauri::command]
pub async fn resume_download(manager: Manager<'_>, id: String) -> Result<(), String> {
    manager.inner().resume(&id).await.map_err(err)
}

#[tauri::command]
pub async fn remove_download(manager: Manager<'_>, id: String, delete_file: bool) -> Result<(), String> {
    manager.remove(&id, delete_file).await.map_err(err)
}

#[tauri::command]
pub async fn open_download(app: AppHandle, manager: Manager<'_>, id: String) -> Result<(), String> {
    let path = manager.file_path(&id).map_err(err)?;
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn reveal_download(app: AppHandle, manager: Manager<'_>, id: String) -> Result<(), String> {
    let path = manager.file_path(&id).map_err(err)?;
    app.opener().reveal_item_in_dir(path).map_err(|e| e.to_string())
}
