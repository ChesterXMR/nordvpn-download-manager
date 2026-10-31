//! Site-specific link preparation.
//!
//! Some file hosts only hand the file to the browser session that produced the link. `prepare`
//! runs before every transfer: it may replace the pasted link with the file's direct address and
//! return the headers (cookies, auth) that every connection of the download must send.
//!
//! gofile.io is handled this way: a `gofile.io/d/<id>` page link (or the file id in a direct
//! `/download/web/<id>/…` link) is exchanged through gofile's API for a direct link the app's own
//! session may fetch, using a temporary guest account, exactly like the site's own JavaScript does.
//! `/download/direct/…` links are public direct links an uploader created and need no session.
//! A website token proves the request comes from the gofile web app: it is
//! `sha256("<user agent>::en-US::<account token>::<4-hour slot>::<salt>")`, with the salt from
//! gofile's `wt.obf.js` (the server recomputes it from the request's user agent, so the two must
//! match). Other gofile links are used as-is with the user's own account token.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;
use wreq::{
    header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE},
    Client,
};

use crate::{browser, mega, settings, util};

const API: &str = "https://api.gofile.io";
/// Salt embedded in gofile's `wt.obf.js`; gofile rotates it occasionally.
const WEBSITE_TOKEN_SALT: &str = "12af056dacea0b";
/// The language is hashed into the website token and sent as `X-BL`.
const LANGUAGE: &str = "en-US";
/// Website tokens rotate with this many-second window, as gofile's JavaScript does.
const TIME_SLOT_SECS: u64 = 4 * 60 * 60;
/// Keyring account holding an automatically created gofile guest token.
const GOFILE_GUEST_TOKEN: &str = "gofile-guest-token";
/// Guest requests are rate-limited; retry a little before giving up.
const ATTEMPTS: u32 = 3;

const TOKEN_HELP: &str = "gofile.io links only download with your own gofile session. In the browser you copy links from, open gofile.io → My profile, copy the Account token, and paste it in Settings.";

pub fn is_gofile(url: &Url) -> bool {
    url.host_str().is_some_and(|h| h == "gofile.io" || h.ends_with(".gofile.io"))
}

/// The `abc123` in `https://gofile.io/d/abc123`, or the file id in a direct link
/// `https://store1.gofile.io/download/web/<file id>/<name>`; gofile's API resolves both.
fn content_id(url: &Url) -> Option<String> {
    if !is_gofile(url) {
        return None;
    }
    let segments: Vec<&str> = url.path().split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        ["d", id] | ["download", "web", id, ..] if !id.is_empty() => Some(id.to_string()),
        _ => None,
    }
}

fn website_token(account_token: &str, slot: u64) -> String {
    let raw = format!(
        "{}::{}::{}::{}::{}",
        browser::CHROME_UA, LANGUAGE, account_token, slot, WEBSITE_TOKEN_SALT
    );
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn current_slot() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / TIME_SLOT_SECS
}

/// Headers the gofile API expects on every request, beyond the browser defaults.
fn api_headers(account_token: &str) -> Vec<(&'static str, String)> {
    vec![
        ("X-Website-Token", website_token(account_token, current_slot())),
        ("X-BL", LANGUAGE.to_owned()),
        ("Origin", "https://gofile.io".to_owned()),
        ("Referer", "https://gofile.io/".to_owned()),
    ]
}

fn gofile_download_headers(account_token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let token = account_token.trim();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&format!("accountToken={token}")).expect("gofile tokens are ASCII"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).expect("gofile tokens are ASCII"),
    );
    headers
}

/// Reads the user's saved gofile token, or the saved guest token, creating one if needed.
async fn account_token(client: &Client) -> Result<String> {
    if let Some(token) = settings::load_secret(settings::GOFILE_TOKEN) {
        return Ok(token);
    }
    if let Some(token) = settings::load_secret(GOFILE_GUEST_TOKEN) {
        return Ok(token);
    }
    create_guest_account(client).await
}

/// Creates a temporary guest account (which needs no website token) and saves its token.
/// Goes through the download's NordVPN client like every other gofile request.
async fn create_guest_account(client: &Client) -> Result<String> {
    #[derive(Deserialize)]
    struct Response {
        status: String,
        data: Guest,
    }
    #[derive(Deserialize)]
    struct Guest {
        token: String,
    }
    let mut last_err = None;
    for attempt in 0..ATTEMPTS {
        let request = client
            .post(format!("{API}/accounts"))
            .header("Origin", "https://gofile.io")
            .header("Referer", "https://gofile.io/");
        match request.send().await {
            Ok(response) => match response.json::<Response>().await {
                Ok(parsed) if parsed.status == "ok" => {
                    settings::save_secret(GOFILE_GUEST_TOKEN, &parsed.data.token)?;
                    return Ok(parsed.data.token);
                }
                Ok(parsed) => last_err = Some(anyhow::anyhow!("gofile.io said: {}", parsed.status)),
                Err(e) => last_err = Some(anyhow::anyhow!(e)),
            },
            Err(e) => last_err = Some(anyhow::anyhow!(e)),
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
        }
    }
    Err(last_err
        .unwrap_or_else(|| anyhow::anyhow!("gofile.io did not answer"))
        .context("Could not create a gofile.io guest account"))
}

#[derive(Deserialize)]
struct ContentResponse {
    status: String,
    data: Content,
}

#[derive(Deserialize)]
struct Content {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    link: Option<String>,
}

/// Exchanges a gofile page link's content id for the file's direct download link.
async fn resolve(client: &Client, content_id: &str) -> Result<(String, HeaderMap)> {
    let token = account_token(client).await?;
    let mut last_err = None;
    for attempt in 0..ATTEMPTS {
        let mut request = client.get(format!("{API}/contents/{content_id}")).query(&[
            ("contentFilter", ""),
            ("page", "1"),
            ("pageSize", "1000"),
            ("sortField", "name"),
            ("sortDirection", "1"),
        ]);
        for (name, value) in api_headers(&token) {
            request = request.header(name, value);
        }
        request = request.header(AUTHORIZATION, format!("Bearer {token}"));

        match request.send().await {
            Ok(response) => match response.json::<ContentResponse>().await {
                Ok(parsed) if parsed.status == "ok" => {
                    let content = parsed.data;
                    if content.kind != "file" {
                        return Err(util::fatal(
                            "That gofile.io link is a folder; paste a link to one file (open the folder, \
                             right-click a file's download button, choose \"Copy link\")",
                        ));
                    }
                    let Some(link) = content.link else {
                        bail!("gofile.io didn't include a download link for that file");
                    };
                    return Ok((link, gofile_download_headers(&token)));
                }
                Ok(parsed) => match parsed.status.as_str() {
                    "error-notFound" => bail!("gofile.io no longer knows that link; copy a fresh one"),
                    "error-passwordRequired" | "error-passwordWrong" => {
                        bail!("That gofile.io link is password protected, which this app can't answer")
                    }
                    "error-notPremium" => {
                        return Err(util::fatal(
                            "gofile.io rejected this app's website token; the site has probably rotated it \
                             and the app needs an update",
                        ))
                    }
                    other => last_err = Some(anyhow::anyhow!("gofile.io said: {other}")),
                },
                Err(e) => last_err = Some(anyhow::anyhow!(e).context("Unexpected response from gofile.io")),
            },
            Err(e) => last_err = Some(anyhow::anyhow!(e)),
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(500 << attempt)).await;
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("gofile.io did not answer")))
}

/// `https://store1.gofile.io/download/direct/<id>/<name>`: a direct link created by the uploader.
fn is_public_direct_link(url: &Url) -> bool {
    url.path().starts_with("/download/direct/")
}

/// Headers a direct `/download/` link needs when it is used as-is.
fn direct_link_headers() -> Result<HeaderMap> {
    let token = settings::load_secret(settings::GOFILE_TOKEN).ok_or_else(|| util::fatal(TOKEN_HELP))?;
    Ok(gofile_download_headers(&token))
}

/// What a transfer needs to fetch a pasted link.
pub struct Prepared {
    /// The address to download, possibly different from the pasted link.
    pub url: String,
    /// Sent with every request (session cookies, auth).
    pub headers: HeaderMap,
    /// Decrypts the received bytes (MEGA files are encrypted).
    pub cipher: Option<mega::Cipher>,
    /// The real file name, when the download address doesn't reveal it.
    pub file_name: Option<String>,
}

impl Prepared {
    fn plain(url: String, headers: HeaderMap) -> Self {
        Self { url, headers, cipher: None, file_name: None }
    }
}

/// Prepares `url` for transfer: possibly replaces the link and adds headers or decryption.
pub async fn prepare(client: &Client, url: &str) -> Result<Prepared> {
    let Ok(parsed) = Url::parse(url) else {
        return Ok(Prepared::plain(url.to_owned(), HeaderMap::new()));
    };
    if let Some(link) = mega::parse(&parsed) {
        let resolved = mega::resolve(client, &link).await?;
        return Ok(Prepared {
            url: resolved.url,
            headers: HeaderMap::new(),
            cipher: Some(resolved.cipher),
            file_name: Some(resolved.name),
        });
    }
    if mega::is_mega(&parsed) {
        return Err(util::fatal("That MEGA link is incomplete; copy it again including the part after #"));
    }
    let (url, headers) = prepare_gofile(client, parsed).await?;
    Ok(Prepared::plain(url, headers))
}

async fn prepare_gofile(client: &Client, mut parsed: Url) -> Result<(String, HeaderMap)> {
    if !is_gofile(&parsed) {
        return Ok((parsed.into(), HeaderMap::new()));
    }
    // gofile requests carry the account token, so they must never go out over plain http.
    let _ = parsed.set_scheme("https");
    if let Some(id) = content_id(&parsed) {
        let (link, headers) = resolve(client, &id).await?;
        let resolved = Url::parse(&link).ok().filter(|u| u.scheme() == "https" && is_gofile(u));
        let Some(resolved) = resolved else {
            bail!("gofile.io returned an unexpected download link");
        };
        return Ok((resolved.into(), headers));
    }
    if is_public_direct_link(&parsed) {
        return Ok((parsed.into(), HeaderMap::new()));
    }
    Ok((parsed.into(), direct_link_headers()?))
}

/// Explains a gofile link that still returned its web page despite the session cookie.
pub fn rejected_message(url: &Url) -> Option<String> {
    is_gofile(url).then(|| {
        if settings::load_secret(settings::GOFILE_TOKEN).is_some()
            || settings::load_secret(GOFILE_GUEST_TOKEN).is_some()
        {
            "gofile.io didn't accept the saved account token for this link. Copy the token again from gofile.io → My profile in the same browser you copied the link from (links expire too, so copy a fresh link).".into()
        } else {
            TOKEN_HELP.into()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nord;

    #[test]
    fn website_token_matches_gofiles_formula() {
        // sha256("<CHROME_UA>::en-US::tok::7::12af056dacea0b")
        assert_eq!(
            website_token("tok", 7),
            "d22e0e29ea294a0a301063110bb0cd47091c147c792f6c5a938824d6adc94e28"
        );
    }

    #[test]
    fn page_links_expose_a_content_id() {
        let parse = |u: &str| Url::parse(u).unwrap();
        assert_eq!(content_id(&parse("https://gofile.io/d/abc123")), Some("abc123".into()));
        assert_eq!(content_id(&parse("https://gofile.io/d/abc123?x=1")), Some("abc123".into()));
        assert_eq!(content_id(&parse("https://gofile.io/")), None);
        assert_eq!(content_id(&parse("https://store1.gofile.io/download/web/xyz/f.mp4")), Some("xyz".into()));
        assert_eq!(content_id(&parse("https://store1.gofile.io/download/direct/xyz/f.mp4")), None);
        assert!(is_public_direct_link(&parse("https://store1.gofile.io/download/direct/xyz/f.mp4")));
        assert_eq!(content_id(&parse("https://store1.gofile.io/download/other")), None);
        assert_eq!(content_id(&parse("https://example.com/d/abc")), None);
    }

    #[tokio::test]
    async fn gofile_links_are_upgraded_to_https() {
        let client = Client::builder().build().unwrap();
        let prepared = prepare(&client, "http://store1.gofile.io/download/direct/xyz/f.mp4").await.unwrap();
        assert_eq!(prepared.url, "https://store1.gofile.io/download/direct/xyz/f.mp4");
        assert!(prepared.headers.is_empty());
        let prepared = prepare(&client, "http://example.com/f.mp4").await.unwrap();
        assert_eq!(prepared.url, "http://example.com/f.mp4", "other sites are left alone");
    }

    /// Talks to the real gofile.io API through a NordVPN server (saved sign-in), as the app does:
    /// `cargo test live_gofile -- --ignored --nocapture`.
    /// Set GOFILE_TEST_URL to a gofile.io link to also test preparing and fetching it.
    #[tokio::test]
    #[ignore]
    async fn live_gofile_guest_account() {
        let api = Client::builder().emulation(browser::emulation()).user_agent(nord::APP_USER_AGENT).build().unwrap();
        let creds = settings::load_credentials().expect("signed in to NordVPN");
        let client = nord::select(&api, &creds, None, &Default::default()).await.expect("NordVPN server").client;
        let token = create_guest_account(&client).await.expect("guest account");
        assert!(!token.is_empty());
        if let Ok(url) = std::env::var("GOFILE_TEST_URL") {
            let prepared = prepare(&client, &url).await.expect("prepared link");
            println!("resolved: {}", prepared.url);
            let response = client.get(&prepared.url).headers(prepared.headers).send().await.unwrap();
            println!("status: {}", response.status());
            assert!(response.status().is_success());
            let content_type = response.headers().get("content-type").and_then(|v| v.to_str().ok());
            assert!(!content_type.is_some_and(|v| v.starts_with("text/html")), "got a web page, not the file");
        }
    }
}
