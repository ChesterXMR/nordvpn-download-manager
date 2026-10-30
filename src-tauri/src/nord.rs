//! NordVPN account sign-in and server selection.
//!
//! Each download gets its own wreq client that tunnels through one NordVPN HTTPS proxy server
//! (TLS to the Nord server, then CONNECT to the target). A server is picked at random from a random
//! country among regions known for fast servers, preferring lightly loaded servers by the load
//! NordVPN publishes, then verified with a single request before use.

use std::{collections::HashSet, sync::OnceLock, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use rand::{seq::SliceRandom, Rng};
use wreq::{Client, Proxy};
use serde::{Deserialize, Serialize};

use crate::{browser, settings::Credentials, util};

const API: &str = "https://api.nordvpn.com/v1";
pub const ACCOUNT_URL: &str = "https://my.nordaccount.com/dashboard/nordvpn/manual-configuration/";
const PROXY_TECHNOLOGY: &str = "proxy_ssl";
const PROXY_PORT: u16 = 89;
/// Countries whose NordVPN servers tend to be fast: Western Europe, North America and East Asia/Oceania hubs.
const FAST_REGIONS: &[&str] = &[
    "GB", "IE", "FR", "DE", "NL", "BE", "LU", "CH", "AT", "DK", "NO", "SE", "FI", "ES", "PT", "IT", "US", "CA",
    "AU", "SG", "JP", "HK",
];
/// Servers at or below this load (%) are preferred; if none are, the least loaded few are used.
const LOW_LOAD: u32 = 40;
/// Random server picks tried before giving up.
const ATTEMPTS: usize = 4;

pub const APP_USER_AGENT: &str = concat!("NordDownloadManager/", env!("CARGO_PKG_VERSION"));
pub const DOWNLOAD_USER_AGENT: &str = browser::CHROME_UA;

#[derive(Debug, Deserialize)]
struct ApiServer {
    name: String,
    hostname: String,
    #[serde(default)]
    load: u32,
    #[serde(default)]
    status: String,
    #[serde(default)]
    locations: Vec<ApiLocation>,
}

#[derive(Debug, Deserialize)]
struct ApiLocation {
    country: ApiCountry,
}

#[derive(Debug, Deserialize)]
struct ApiCountry {
    name: String,
    code: String,
    #[serde(default)]
    city: Option<ApiCity>,
}

#[derive(Debug, Deserialize)]
struct ApiCity {
    name: String,
}

#[derive(Debug, Deserialize)]
struct Insights {
    ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfo {
    pub hostname: String,
    pub name: String,
    pub country: String,
    pub country_code: String,
    pub city: Option<String>,
    pub load: u32,
    /// Public IP the target server sees, as reported by NordVPN through the proxy.
    pub exit_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Country {
    pub id: u64,
    pub name: String,
    pub code: String,
}

/// A verified NordVPN server and the client that tunnels through it.
pub struct Selected {
    pub info: ServerInfo,
    pub client: Client,
}

static COUNTRIES: OnceLock<Vec<Country>> = OnceLock::new();

pub async fn countries(api: &Client) -> Result<Vec<Country>> {
    if let Some(cached) = COUNTRIES.get() {
        return Ok(cached.clone());
    }
    let mut countries: Vec<Country> = api
        .get(format!("{API}/servers/countries"))
        .send()
        .await
        .context("Could not reach the NordVPN API")?
        .error_for_status()?
        .json()
        .await
        .context("Unexpected response from the NordVPN API")?;
    countries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(COUNTRIES.get_or_init(|| countries).clone())
}

/// Exchanges a Nord Account access token for the account's service credentials.
pub async fn credentials_from_token(api: &Client, token: &str) -> Result<Credentials> {
    #[derive(Deserialize)]
    struct Response {
        username: String,
        password: String,
    }
    let response = api
        .get(format!("{API}/users/services/credentials"))
        .basic_auth("token", Some(token.trim()))
        .send()
        .await
        .context("Could not reach the NordVPN API")?;
    if matches!(response.status().as_u16(), 401 | 403) {
        bail!("NordVPN didn't accept that access token. Check you copied all of it, or generate a new one.");
    }
    let creds: Response = response.error_for_status()?.json().await?;
    Ok(Credentials { username: creds.username, password: creds.password })
}

/// Checks the credentials against a few nearby NordVPN proxy servers.
pub async fn verify_credentials(api: &Client, creds: &Credentials) -> Result<()> {
    if creds.username.contains('@') {
        bail!("That's your Nord account e-mail. NordVPN's servers only accept your service credentials, or sign in with an access token instead.");
    }
    let servers = server_list(api, None).await?;
    let mut last_err = None;
    for server in servers.iter().take(3) {
        let client = proxied_client(&server.hostname, creds)?;
        match tokio::time::timeout(Duration::from_secs(12), insights(&client)).await {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) if is_auth_error(&e) => {
                bail!("NordVPN didn't accept these service credentials. Copy them again from Nord Account, or sign in with an access token.")
            }
            Ok(Err(e)) => last_err = Some(e),
            Err(_) => last_err = Some(anyhow!("timed out")),
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow!("no server answered"))
        .context("Couldn't reach a NordVPN server to check the credentials"))
}

/// The HTTPS proxy's certificate is issued for `*.proxy.nordvpn.com`, so `nl123.nordvpn.com` must be
/// addressed as `nl123.proxy.nordvpn.com` (same IP) for TLS verification to succeed.
fn proxy_host(hostname: &str) -> String {
    match hostname.strip_suffix(".nordvpn.com") {
        Some(server) if !server.ends_with(".proxy") => format!("{server}.proxy.nordvpn.com"),
        _ => hostname.to_string(),
    }
}

pub fn proxied_client(hostname: &str, creds: &Credentials) -> Result<Client> {
    let mut proxy_url = url::Url::parse(&format!("https://{}:{PROXY_PORT}", proxy_host(hostname)))?;
    proxy_url
        .set_username(&creds.username)
        .map_err(|_| anyhow!("Invalid proxy username"))?;
    proxy_url
        .set_password(Some(&creds.password))
        .map_err(|_| anyhow!("Invalid proxy password"))?;
    // Setting an explicit proxy also disables the system proxy, so nothing bypasses NordVPN.
    Ok(Client::builder()
        .emulation(browser::emulation())
        .proxy(Proxy::all(proxy_url.as_str())?)
        .user_agent(DOWNLOAD_USER_AGENT)
        .redirect(wreq::redirect::Policy::limited(10))
        .connect_timeout(Duration::from_secs(20))
        .read_timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()?)
}

/// Picks a random lightly loaded server, in `country_id` or else a random fast-region country,
/// skipping servers in `exclude`, and verifies traffic really exits through it.
pub async fn select(api: &Client, creds: &Credentials, country_id: Option<u64>, exclude: &HashSet<String>) -> Result<Selected> {
    let (direct_ip, countries) = tokio::join!(async { insights(api).await.ok().map(|i| i.ip) }, async {
        match country_id {
            Some(id) => Ok(vec![id]),
            None => fast_region_ids(api).await,
        }
    });
    let countries = countries?;
    let mut tried = exclude.clone();
    let mut last_err = None;
    for _ in 0..ATTEMPTS {
        let country = *countries.choose(&mut rand::thread_rng()).expect("at least one country");
        let server = match pick_server(api, country, &tried).await {
            Ok(server) => server,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };
        tried.insert(server.hostname.clone());
        match connect(server, creds, direct_ip.as_deref()).await {
            Ok(selected) => return Ok(selected),
            Err(e) if util::is_fatal(&e) => return Err(e),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("Could not connect to any NordVPN server")))
}

async fn fast_region_ids(api: &Client) -> Result<Vec<u64>> {
    let ids: Vec<u64> = countries(api)
        .await?
        .into_iter()
        .filter(|c| FAST_REGIONS.contains(&c.code.as_str()))
        .map(|c| c.id)
        .collect();
    if ids.is_empty() {
        bail!("NordVPN's country list didn't include any of the preferred regions");
    }
    Ok(ids)
}

/// A random online server in the country, chosen among the lightly loaded ones.
async fn pick_server(api: &Client, country_id: u64, skip: &HashSet<String>) -> Result<ApiServer> {
    let mut servers = server_list(api, Some(country_id)).await?;
    servers.retain(|s| !skip.contains(&s.hostname) && (s.status.is_empty() || s.status == "online"));
    if servers.is_empty() {
        bail!("No free NordVPN proxy servers in the chosen country");
    }
    servers.sort_by_key(|s| s.load);
    let quiet = servers.iter().filter(|s| s.load <= LOW_LOAD).count();
    let eligible = if quiet > 0 { quiet } else { servers.len().min(5) };
    let pick = rand::thread_rng().gen_range(0..eligible);
    Ok(servers.swap_remove(pick))
}

/// Proxy servers for a country, or the ones nearest to the user when `country_id` is `None`.
async fn server_list(api: &Client, country_id: Option<u64>) -> Result<Vec<ApiServer>> {
    let mut query = vec![
        ("filters[servers_technologies][identifier]", PROXY_TECHNOLOGY.to_string()),
        ("limit", "40".to_string()),
    ];
    if let Some(id) = country_id {
        query.push(("filters[country_id]", id.to_string()));
    }
    api.get(format!("{API}/servers/recommendations"))
        .query(&query)
        .send()
        .await
        .context("Could not reach the NordVPN API")?
        .error_for_status()?
        .json()
        .await
        .context("Unexpected server list from the NordVPN API")
}

async fn insights(client: &Client) -> Result<Insights> {
    Ok(client
        .get(format!("{API}/helpers/ips/insights"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn connect(server: ApiServer, creds: &Credentials, direct_ip: Option<&str>) -> Result<Selected> {
    let host = server.hostname;
    let client = proxied_client(&host, creds)?;
    let insights = match tokio::time::timeout(Duration::from_secs(12), insights(&client)).await {
        Ok(Ok(insights)) => insights,
        Ok(Err(e)) if is_auth_error(&e) => {
            return Err(util::fatal("NordVPN rejected the saved credentials. Sign in again in Settings."))
        }
        Ok(Err(e)) => return Err(e.context(format!("{host} did not respond"))),
        Err(_) => bail!("{host} timed out"),
    };
    if direct_ip == Some(insights.ip.as_str()) {
        bail!("Traffic sent through {host} still left from your own IP address; refusing to use it");
    }
    let location = server.locations.first();
    Ok(Selected {
        info: ServerInfo {
            name: server.name,
            country: location.map(|l| l.country.name.clone()).unwrap_or_default(),
            country_code: location.map(|l| l.country.code.clone()).unwrap_or_default(),
            city: location.and_then(|l| l.country.city.as_ref()).map(|c| c.name.clone()),
            load: server.load,
            exit_ip: Some(insights.ip),
            hostname: host,
        },
        client,
    })
}

fn is_auth_error(e: &anyhow::Error) -> bool {
    let text = format!("{e:#}").to_lowercase();
    // reqwest reports a 407 on CONNECT as "proxy authorization required".
    text.contains("407") || text.contains("proxy auth")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_proxy_uses_certificate_hostname() {
        assert_eq!(proxy_host("nl812.nordvpn.com"), "nl812.proxy.nordvpn.com");
        assert_eq!(proxy_host("nl812.proxy.nordvpn.com"), "nl812.proxy.nordvpn.com");
    }

    /// Talks to the real NordVPN API and proxies: `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_sign_in_rejects_bad_credentials() {
        let api = Client::builder().user_agent(APP_USER_AGENT).build().unwrap();
        let bogus = Credentials { username: "invalid-user".into(), password: "invalid-pass".into() };
        let err = verify_credentials(&api, &bogus).await.unwrap_err().to_string();
        assert!(err.contains("didn't accept these service credentials"), "{err}");

        let email = Credentials { username: "someone@example.com".into(), password: "x".into() };
        let err = verify_credentials(&api, &email).await.unwrap_err().to_string();
        assert!(err.contains("account e-mail"), "{err}");

        let err = credentials_from_token(&api, "0".repeat(64).as_str()).await.err().unwrap().to_string();
        assert!(err.contains("access token"), "{err}");
    }
}
