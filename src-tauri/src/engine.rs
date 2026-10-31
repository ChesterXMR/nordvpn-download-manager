//! Segmented download engine.
//!
//! A file is split into byte-range segments fetched in parallel, one connection per worker, all
//! through the NordVPN proxy client chosen for that download. There is no direct-connection
//! fallback. When a worker finishes early it steals half of the largest remaining segment, so all
//! connections stay busy until the very end. Progress is persisted, so downloads resume across
//! restarts (on a freshly chosen server).

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering::Relaxed},
        Arc, Mutex, MutexGuard, PoisonError,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use wreq::{
    header::{self, HeaderMap},
    Client, StatusCode,
};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager};

/// Delivers an event to the UI. Kept abstract so the engine runs without a window in tests.
pub type EventSink = Box<dyn Fn(&str, serde_json::Value) + Send + Sync>;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    browser, mega,
    nord::{self, Selected, ServerInfo},
    recommend::{self, MAX_CONNECTIONS},
    settings::{self, Credentials, Settings},
    sites, util,
};

/// Bytes buffered per connection before writing to disk.
const FLUSH_SIZE: usize = 256 << 10;
/// Segments are never split into pieces smaller than this.
const MIN_SPLIT: u64 = 2 << 20;
/// Consecutive failed attempts (without progress) before a worker gives up on a segment.
const MAX_SEGMENT_RETRIES: u32 = 5;
/// NordVPN servers tried before a download is marked as failed.
const MAX_SERVER_ATTEMPTS: usize = 5;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Segment {
    pub start: u64,
    /// Exclusive. `u64::MAX` while the total size is unknown.
    pub end: u64,
    pub pos: u64,
    #[serde(skip)]
    busy: bool,
}

impl Segment {
    fn new(start: u64, end: u64) -> Self {
        Self { start, end, pos: start, busy: false }
    }

    fn remaining(&self) -> u64 {
        self.end.saturating_sub(self.pos)
    }
}

fn initial_segments(total: u64, connections: u32) -> Vec<Segment> {
    if total == 0 {
        return Vec::new();
    }
    let n = (connections.max(1) as u64).min(total.div_ceil(MIN_SPLIT)).max(1);
    let size = total / n;
    (0..n)
        .map(|i| Segment::new(i * size, if i + 1 == n { total } else { (i + 1) * size }))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Connecting,
    Downloading,
    Paused,
    Completed,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadRecord {
    pub id: String,
    pub url: String,
    pub file_name: String,
    pub dir: String,
    pub total_size: Option<u64>,
    pub resumable: bool,
    pub connections: u32,
    pub segments: Vec<Segment>,
    pub status: Status,
    pub error: Option<String>,
    pub server: Option<ServerInfo>,
    pub status_text: Option<String>,
    pub created_at: u64,
    pub completed_at: Option<u64>,
    /// Size and range support are known and `segments` is initialised.
    #[serde(default)]
    prepared: bool,
    /// The name was guessed from the URL and may be replaced by the server's Content-Disposition.
    #[serde(default)]
    auto_name: bool,
    /// A MEGA folder link: `file_name` is a folder and `segments[i]` tracks `folder[i]`'s bytes.
    #[serde(default)]
    pub is_folder: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    folder: Vec<FolderEntry>,
}

/// One file of a folder download.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FolderEntry {
    handle: String,
    /// Path below the download's folder, '/'-separated, every part sanitized.
    path: String,
    size: u64,
}

/// Segments as the progress bar needs them: finished neighbours merged, untouched ones dropped.
/// Keeps updates small for folders with thousands of files.
fn display_segments(segments: &[Segment]) -> Vec<Segment> {
    let mut out: Vec<Segment> = Vec::new();
    for s in segments.iter().filter(|s| s.pos > s.start) {
        match out.last_mut() {
            Some(last) if last.pos >= last.end && last.end == s.start => {
                last.end = s.end;
                last.pos = s.pos;
            }
            _ => out.push(s.clone()),
        }
    }
    out
}

impl DownloadRecord {
    fn downloaded(&self) -> u64 {
        self.segments.iter().map(|s| s.pos - s.start).sum()
    }

    /// The record as the UI sees it, without the (possibly huge) folder file list.
    fn for_display(&self) -> Self {
        let mut rec = self.clone();
        rec.folder = Vec::new();
        rec.segments = display_segments(&self.segments);
        rec
    }

    fn apply_probe(&mut self, probe: &Probe) {
        self.total_size = probe.size;
        self.resumable = probe.resumable;
        if probe.resumable {
            self.segments = initial_segments(probe.size.unwrap_or(0), self.connections);
        } else {
            self.connections = 1;
            self.segments = Vec::new();
        }
        self.prepared = true;
    }

    fn part_path(&self) -> PathBuf {
        if self.is_folder {
            return self.final_path();
        }
        Path::new(&self.dir).join(format!("{}.part", self.file_name))
    }

    fn final_path(&self) -> PathBuf {
        Path::new(&self.dir).join(&self.file_name)
    }

    fn is_active(&self) -> bool {
        matches!(self.status, Status::Connecting | Status::Downloading)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadView {
    #[serde(flatten)]
    pub record: DownloadRecord,
    pub downloaded: u64,
    pub speed: f64,
    pub active_connections: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressUpdate {
    id: String,
    downloaded: u64,
    total_size: Option<u64>,
    speed: f64,
    eta: Option<f64>,
    active_connections: u32,
    segments: Vec<Segment>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddRequest {
    pub url: String,
    #[serde(default)]
    pub connections: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct Probe {
    pub file_name: String,
    pub size: Option<u64>,
    pub resumable: bool,
}

/// Asks for the first byte to learn the size, whether ranges work, and the file name.
async fn probe(client: &Client, url: &str, headers: &HeaderMap) -> Result<Probe> {
    let response = client
        .get(url)
        .headers(headers.clone())
        .header(header::RANGE, "bytes=0-0")
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .context("Could not reach the link through the NordVPN server")?;
    let status = response.status();
    let headers = response.headers().clone();
    let final_url = uri_to_url(response.uri());
    drop(response);

    // File hosts that need a browser session answer with their web page instead of the file.
    let is_html = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/html"));
    if status.is_success() && is_html && util::filename_from_headers(&headers).is_none() {
        if let Some(message) = sites::rejected_message(&final_url) {
            return Err(util::fatal(message));
        }
        // Typically a bot check (e.g. Cloudflare "Just a moment...") shown to some VPN IPs only.
        let host = final_url.host_str().unwrap_or("The site");
        return Err(util::blocked(format!("{host} showed a web page (likely a bot check) to this NordVPN server instead of the file")));
    }

    let (size, resumable) = match status {
        StatusCode::PARTIAL_CONTENT => {
            let total = headers
                .get(header::CONTENT_RANGE)
                .and_then(|v| v.to_str().ok())
                .and_then(util::parse_content_range)
                .and_then(|(_, total)| total);
            (total, total.is_some())
        }
        s if s.is_success() => (
            headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok()),
            false,
        ),
        s => return Err(util::http_error(s)),
    };
    let file_name = util::filename_from_headers(&headers)
        .or_else(|| util::filename_from_url(&final_url))
        .or_else(|| Url::parse(url).ok().as_ref().and_then(util::filename_from_url))
        .unwrap_or_else(|| "download".into());
    Ok(Probe { file_name: util::sanitize_filename(&file_name), size, resumable })
}

/// The final URI after redirects, as a `Url` for the filename/rejection helpers.
fn uri_to_url(uri: &wreq::Uri) -> url::Url {
    Url::parse(&uri.to_string()).unwrap_or_else(|_| "https://invalid.invalid".parse().unwrap())
}

fn validate_url(raw: &str) -> Result<String> {
    let url = Url::parse(raw.trim()).map_err(|_| anyhow!("That doesn't look like a valid link"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("Only http:// and https:// links are supported");
    }
    Ok(url.to_string())
}

struct Download {
    rec: Mutex<DownloadRecord>,
    run: Mutex<Option<Run>>,
    /// Bytes received since the last progress tick.
    received: AtomicU64,
    speed: Mutex<f64>,
    active: AtomicU32,
}

impl Download {
    fn new(rec: DownloadRecord) -> Self {
        Self {
            rec: Mutex::new(rec),
            run: Mutex::new(None),
            received: AtomicU64::new(0),
            speed: Mutex::new(0.0),
            active: AtomicU32::new(0),
        }
    }

    fn view(&self) -> DownloadView {
        let (record, downloaded) = {
            let rec = lock(&self.rec);
            (rec.for_display(), rec.downloaded())
        };
        DownloadView {
            downloaded,
            speed: *lock(&self.speed),
            active_connections: self.active.load(Relaxed),
            record,
        }
    }
}

struct Run {
    cancel: CancellationToken,
    handle: tauri::async_runtime::JoinHandle<()>,
}

enum Outcome {
    Completed,
    Cancelled,
}

pub struct DownloadManager {
    events: EventSink,
    /// Direct client, used only for the NordVPN API (server lists, credentials). Never for downloads.
    api: Client,
    data_dir: PathBuf,
    settings: Mutex<Settings>,
    downloads: Mutex<Vec<Arc<Download>>>,
}

impl DownloadManager {
    pub fn load(app: AppHandle) -> Result<Arc<Self>> {
        let data_dir = app.path().app_data_dir()?;
        let default_dir = app.path().download_dir().unwrap_or_default();
        let events: EventSink = Box::new(move |event, payload| {
            let _ = app.emit(event, payload);
        });
        Self::new(events, data_dir, default_dir)
    }

    pub fn new(events: EventSink, data_dir: PathBuf, default_download_dir: PathBuf) -> Result<Arc<Self>> {
        fs::create_dir_all(&data_dir)?;
        let mut settings = settings::load(&data_dir.join("settings.json"));
        if settings.download_dir.is_empty() {
            settings.download_dir = default_download_dir.to_string_lossy().into_owned();
        }
        let records: Vec<DownloadRecord> = fs::read(data_dir.join("downloads.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default();
        let downloads = records
            .into_iter()
            .map(|mut rec| {
                if rec.is_active() {
                    rec.status = Status::Paused;
                    rec.status_text = None;
                }
                Arc::new(Download::new(rec))
            })
            .collect();
        let api = Client::builder()
            .emulation(browser::emulation())
            .user_agent(nord::APP_USER_AGENT)
            .redirect(wreq::redirect::Policy::limited(10))
            .timeout(Duration::from_secs(20))
            .build()?;
        let manager = Arc::new(Self {
            events,
            api,
            data_dir,
            settings: Mutex::new(settings),
            downloads: Mutex::new(downloads),
        });
        manager.spawn_ticker();
        Ok(manager)
    }

    pub fn api(&self) -> &Client {
        &self.api
    }

    pub fn settings(&self) -> Settings {
        lock(&self.settings).clone()
    }

    pub fn save_settings(&self, settings: Settings) -> Result<()> {
        settings::save(&self.data_dir.join("settings.json"), &settings)?;
        *lock(&self.settings) = settings;
        Ok(())
    }

    fn credentials(&self) -> Result<Credentials> {
        settings::load_credentials()
            .ok_or_else(|| util::fatal("Sign in to NordVPN in Settings first."))
    }

    /// The download list is never locked together with a download's record: callers iterate a
    /// snapshot and lock records one at a time, so lock ordering can't deadlock.
    fn snapshot(&self) -> Vec<Arc<Download>> {
        lock(&self.downloads).clone()
    }

    pub fn active_count(&self) -> usize {
        self.snapshot().iter().filter(|d| lock(&d.rec).is_active()).count()
    }

    fn servers_in_use(&self, except_id: &str) -> HashSet<String> {
        self.snapshot()
            .iter()
            .filter_map(|d| {
                let rec = lock(&d.rec);
                if rec.id == except_id || !rec.is_active() {
                    return None;
                }
                rec.server.as_ref().map(|s| s.hostname.clone())
            })
            .collect()
    }

    async fn select_server(&self, except_id: &str, also_exclude: &HashSet<String>) -> Result<Selected> {
        let creds = self.credentials()?;
        let country_id = self.settings().country_id;
        let mut exclude = self.servers_in_use(except_id);
        exclude.extend(also_exclude.iter().cloned());
        nord::select(&self.api, &creds, country_id, &exclude).await
    }

    pub fn add(self: &Arc<Self>, request: AddRequest) -> Result<DownloadView> {
        let url = validate_url(&request.url)?;
        self.credentials()?;
        let dir = self.settings().download_dir;
        if dir.is_empty() {
            bail!("Choose a download folder in Settings first");
        }
        let parsed = Url::parse(&url).ok();
        let is_folder = matches!(
            parsed.as_ref().and_then(mega::parse),
            Some(mega::Link::Folder { file: None, .. })
        );
        // A provisional name from the URL; replaced by the server's file name once the link is probed.
        let name = parsed
            .as_ref()
            .and_then(util::filename_from_url)
            .unwrap_or_else(|| "download".into());
        let file_name = util::unique_name(
            Path::new(&dir),
            &util::sanitize_filename(&name),
            &self.names_in(&dir, ""),
            true,
        );
        let connections = request
            .connections
            .unwrap_or_else(|| recommend::recommend(None, true, self.active_count()).connections)
            .clamp(1, MAX_CONNECTIONS);

        let rec = DownloadRecord {
            id: uuid::Uuid::new_v4().to_string(),
            url,
            file_name,
            dir,
            total_size: None,
            resumable: true,
            connections,
            segments: Vec::new(),
            status: Status::Connecting,
            error: None,
            server: None,
            status_text: None,
            created_at: util::now_secs(),
            completed_at: None,
            prepared: false,
            auto_name: true,
            is_folder,
            folder: Vec::new(),
        };
        let download = Arc::new(Download::new(rec));
        lock(&self.downloads).insert(0, download.clone());
        self.persist();
        self.start(&download);
        Ok(download.view())
    }

    pub fn list(&self) -> Vec<DownloadView> {
        self.snapshot().iter().map(|d| d.view()).collect()
    }

    fn find(&self, id: &str) -> Result<Arc<Download>> {
        self.snapshot()
            .iter()
            .find(|d| lock(&d.rec).id == id)
            .cloned()
            .ok_or_else(|| anyhow!("Download not found"))
    }

    /// Lowercased names of unfinished downloads in `dir`, so two downloads never share a `.part` file.
    fn names_in(&self, dir: &str, except_id: &str) -> HashSet<String> {
        self.snapshot()
            .iter()
            .filter_map(|d| {
                let rec = lock(&d.rec);
                (rec.id != except_id && rec.status != Status::Completed && rec.dir.eq_ignore_ascii_case(dir))
                    .then(|| rec.file_name.to_lowercase())
            })
            .collect()
    }

    pub fn file_path(&self, id: &str) -> Result<PathBuf> {
        let download = self.find(id)?;
        let rec = lock(&download.rec);
        let path = if rec.status == Status::Completed { rec.final_path() } else { rec.part_path() };
        Ok(if path.exists() { path } else { PathBuf::from(&rec.dir) })
    }

    pub async fn pause(&self, id: &str) -> Result<()> {
        let download = self.find(id)?;
        self.stop(&download).await;
        Ok(())
    }

    pub async fn resume(self: &Arc<Self>, id: &str) -> Result<()> {
        let download = self.find(id)?;
        let status = lock(&download.rec).status;
        if !matches!(status, Status::Paused | Status::Error) {
            return Ok(());
        }
        self.credentials()?;
        self.stop(&download).await;
        self.start(&download);
        Ok(())
    }

    pub async fn remove(&self, id: &str, delete_file: bool) -> Result<()> {
        let download = self.find(id)?;
        self.stop(&download).await;
        lock(&self.downloads).retain(|d| !Arc::ptr_eq(d, &download));
        let (status, part, final_path, folder) = {
            let rec = lock(&download.rec);
            (rec.status, rec.part_path(), rec.final_path(), rec.folder.clone())
        };
        if status != Status::Completed {
            // A folder download only leaves partial `.part` files; finished files are kept.
            for entry in &folder {
                let _ = fs::remove_file(part_file(&final_path.join(&entry.path)));
            }
            let _ = fs::remove_file(part);
        } else if delete_file {
            let _ = fs::remove_file(final_path);
        }
        self.persist();
        self.emit("download-removed", id);
        Ok(())
    }

    /// Cancels a running download and waits until its workers have stopped writing.
    async fn stop(&self, download: &Arc<Download>) {
        let run = lock(&download.run).take();
        if let Some(run) = run {
            run.cancel.cancel();
            let _ = run.handle.await;
        }
    }

    fn start(self: &Arc<Self>, download: &Arc<Download>) {
        {
            let mut rec = lock(&download.rec);
            rec.status = Status::Connecting;
            rec.error = None;
        }
        self.emit_update(download);
        let cancel = CancellationToken::new();
        let manager = self.clone();
        let task_download = download.clone();
        let task_cancel = cancel.clone();
        let handle = tauri::async_runtime::spawn(async move {
            let result = manager.run(&task_download, &task_cancel).await;
            {
                let mut rec = lock(&task_download.rec);
                rec.status_text = None;
                match result {
                    Ok(Outcome::Completed) => {
                        rec.status = Status::Completed;
                        rec.completed_at = Some(util::now_secs());
                    }
                    Ok(Outcome::Cancelled) => rec.status = Status::Paused,
                    Err(_) if task_cancel.is_cancelled() => rec.status = Status::Paused,
                    Err(e) => {
                        rec.status = Status::Error;
                        rec.error = Some(format!("{e:#}"));
                    }
                }
            }
            task_download.active.store(0, Relaxed);
            *lock(&task_download.speed) = 0.0;
            manager.persist();
            manager.emit_update(&task_download);
        });
        *lock(&download.run) = Some(Run { cancel, handle });
    }

    fn set_status(&self, download: &Arc<Download>, status: Status, text: Option<String>) {
        {
            let mut rec = lock(&download.rec);
            rec.status = status;
            rec.status_text = text;
        }
        self.emit_update(download);
    }

    /// Picks a server and transfers, moving to another server on network failures.
    async fn run(&self, download: &Arc<Download>, cancel: &CancellationToken) -> Result<Outcome> {
        let id = lock(&download.rec).id.clone();
        let mut failed_servers = HashSet::new();
        let mut last_err = None;
        for _ in 0..MAX_SERVER_ATTEMPTS {
            self.set_status(download, Status::Connecting, Some("Connecting to NordVPN…".into()));
            let server = tokio::select! {
                _ = cancel.cancelled() => return Ok(Outcome::Cancelled),
                server = self.select_server(&id, &failed_servers) => server?,
            };
            let host = server.info.hostname.clone();
            {
                let mut rec = lock(&download.rec);
                rec.status_text = Some(format!("Connected via {} ({})", host, server.info.country));
                rec.server = Some(server.info.clone());
            }
            self.emit_update(download);
            match self.transfer(download, &server.client, cancel).await {
                Ok(outcome) => return Ok(outcome),
                Err(_) if cancel.is_cancelled() => return Ok(Outcome::Cancelled),
                Err(e) if util::is_fatal(&e) => return Err(e),
                Err(e) => {
                    let reason = if util::is_blocked(&e) { "blocked" } else { "failed" };
                    self.set_status(download, Status::Connecting, Some(format!("{host} {reason}, switching server…")));
                    failed_servers.insert(host);
                    last_err = Some(e);
                }
            }
        }
        Err(last_err
            .unwrap_or_else(|| anyhow!("Download failed"))
            .context(format!("Gave up after {MAX_SERVER_ATTEMPTS} NordVPN servers")))
    }

    async fn transfer(&self, download: &Arc<Download>, client: &Client, cancel: &CancellationToken) -> Result<Outcome> {
        let (url, prepared, is_folder) = {
            let rec = lock(&download.rec);
            (rec.url.clone(), rec.prepared, rec.is_folder)
        };
        if is_folder {
            let link = Url::parse(&url).ok().as_ref().and_then(mega::parse);
            let Some(mega::Link::Folder { handle, key, .. }) = link else {
                return Err(util::fatal("This MEGA folder link can no longer be read"));
            };
            return self.transfer_folder(download, client, &handle, &key, cancel).await;
        }
        self.set_status(download, Status::Connecting, Some("Inspecting the link…".into()));
        // Site-specific preparation may replace the pasted link (a gofile page link becomes the
        // file's direct address) and produce headers every connection must send.
        let site = tokio::select! {
            _ = cancel.cancelled() => return Ok(Outcome::Cancelled),
            prepared = sites::prepare(client, &url) => prepared?,
        };
        if !prepared {
            let probe = tokio::select! {
                _ = cancel.cancelled() => return Ok(Outcome::Cancelled),
                probe = probe(client, &site.url, &site.headers) => probe?,
            };
            let (id, dir, auto_name) = {
                let rec = lock(&download.rec);
                (rec.id.clone(), rec.dir.clone(), rec.auto_name)
            };
            let taken = if auto_name { self.names_in(&dir, &id) } else { HashSet::new() };
            let name = site.file_name.as_deref().map(util::sanitize_filename).unwrap_or(probe.file_name.clone());
            let mut rec = lock(&download.rec);
            if auto_name {
                rec.file_name = util::unique_name(Path::new(&dir), &name, &taken, true);
                rec.auto_name = false;
            }
            rec.apply_probe(&probe);
        }

        let part_path = lock(&download.rec).part_path();
        self.set_status(download, Status::Downloading, None);
        run_workers(download, client, &site.headers, &site.url, site.cipher, &part_path, cancel).await?;
        if cancel.is_cancelled() {
            return Ok(Outcome::Cancelled);
        }
        self.finalize(download, &part_path)?;
        Ok(Outcome::Completed)
    }

    /// Downloads every file of a MEGA folder, `connections` files at a time, into a folder
    /// named after it. Finished files are kept across pauses, restarts and server switches.
    async fn transfer_folder(
        &self,
        download: &Arc<Download>,
        client: &Client,
        handle: &str,
        key: &[u8; 16],
        cancel: &CancellationToken,
    ) -> Result<Outcome> {
        self.set_status(download, Status::Connecting, Some("Reading the MEGA folder…".into()));
        let (root, files) = tokio::select! {
            _ = cancel.cancelled() => return Ok(Outcome::Cancelled),
            listed = mega::list_folder(client, handle, key) => listed?,
        };
        if !lock(&download.rec).prepared {
            let (id, dir) = {
                let rec = lock(&download.rec);
                (rec.id.clone(), rec.dir.clone())
            };
            let taken = self.names_in(&dir, &id);
            let name = util::unique_name(Path::new(&dir), &util::sanitize_filename(&root), &taken, true);
            let mut rec = lock(&download.rec);
            rec.file_name = name;
            rec.auto_name = false;
            // MEGA allows duplicate names in a folder; Windows doesn't.
            let mut seen = HashSet::new();
            rec.folder = files
                .iter()
                .map(|f| {
                    let base = f.dir.iter().chain([&f.name]).map(|p| util::sanitize_filename(p)).collect::<Vec<_>>().join("/");
                    let path = (0..).map(|n| numbered(&base, n)).find(|p| seen.insert(p.to_lowercase())).unwrap();
                    FolderEntry { handle: f.handle.clone(), path, size: f.size }
                })
                .collect();
            let mut offset = 0;
            rec.segments = rec
                .folder
                .iter()
                .map(|f| {
                    let segment = Segment::new(offset, offset + f.size);
                    offset += f.size;
                    segment
                })
                .collect();
            rec.total_size = Some(offset);
            rec.resumable = true;
            rec.prepared = true;
        }
        let keys: HashMap<String, [u8; 32]> = files.into_iter().map(|f| (f.handle, f.key)).collect();
        let (root_dir, connections, url) = {
            let rec = lock(&download.rec);
            (rec.final_path(), rec.connections, rec.url.clone())
        };

        let job = Arc::new(FolderJob {
            download: download.clone(),
            client: client.clone(),
            folder: handle.to_owned(),
            keys,
            root_dir,
            source_url: url,
            cancel: cancel.clone(),
        });
        job.reconcile()?;
        self.set_status(download, Status::Downloading, None);
        let mut workers = tokio::task::JoinSet::new();
        for _ in 0..connections {
            workers.spawn(job.clone().worker());
        }
        let last_err = join_workers(&mut workers).await;
        if cancel.is_cancelled() {
            return Ok(Outcome::Cancelled);
        }
        let mut rec = lock(&download.rec);
        if rec.segments.iter().all(|s| s.pos >= s.end) {
            // The per-file bookkeeping is no longer needed; keep the saved list small.
            let total = rec.total_size.unwrap_or(0);
            rec.segments = vec![Segment { start: 0, end: total, pos: total, busy: false }];
            rec.folder = Vec::new();
            return Ok(Outcome::Completed);
        }
        Err(last_err.unwrap_or_else(|| anyhow!("The download stopped before finishing")))
    }

    fn finalize(&self, download: &Arc<Download>, part_path: &Path) -> Result<()> {
        let mut rec = lock(&download.rec);
        let dir = PathBuf::from(&rec.dir);
        let name = util::unique_name(&dir, &rec.file_name, &HashSet::new(), false);
        let path = dir.join(&name);
        fs::rename(part_path, &path)
            .map_err(|e| util::fatal(format!("Could not move the finished file into place: {e}")))?;
        util::mark_from_internet(&path, &rec.url);
        rec.file_name = name;
        Ok(())
    }

    fn emit(&self, event: &str, payload: impl Serialize) {
        if let Ok(value) = serde_json::to_value(payload) {
            (self.events)(event, value);
        }
    }

    fn emit_update(&self, download: &Arc<Download>) {
        self.emit("download-updated", download.view());
    }

    fn persist(&self) {
        let records: Vec<DownloadRecord> = self.snapshot().iter().map(|d| lock(&d.rec).clone()).collect();
        let path = self.data_dir.join("downloads.json");
        let tmp = path.with_extension("json.tmp");
        if let Ok(json) = serde_json::to_vec(&records) {
            if fs::write(&tmp, json).is_ok() {
                let _ = fs::rename(&tmp, &path);
            }
        }
    }

    /// Emits progress for running downloads twice a second and checkpoints state every few seconds.
    fn spawn_ticker(self: &Arc<Self>) {
        let manager = self.clone();
        tauri::async_runtime::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(500));
            let mut last = Instant::now();
            let mut ticks = 0u64;
            loop {
                interval.tick().await;
                let elapsed = last.elapsed().as_secs_f64().max(0.001);
                last = Instant::now();
                ticks += 1;
                let mut updates = Vec::new();
                for download in manager.snapshot().iter() {
                    let received = download.received.swap(0, Relaxed);
                    let rec = lock(&download.rec);
                    let mut speed = lock(&download.speed);
                    if rec.status != Status::Downloading {
                        *speed = 0.0;
                        continue;
                    }
                    let instant = received as f64 / elapsed;
                    *speed = if *speed == 0.0 { instant } else { *speed * 0.75 + instant * 0.25 };
                    let downloaded = rec.downloaded();
                    updates.push(ProgressUpdate {
                        id: rec.id.clone(),
                        downloaded,
                        total_size: rec.total_size,
                        speed: *speed,
                        eta: rec
                            .total_size
                            .filter(|_| *speed > 1.0)
                            .map(|total| total.saturating_sub(downloaded) as f64 / *speed),
                        active_connections: download.active.load(Relaxed),
                        segments: display_segments(&rec.segments),
                    });
                }
                if !updates.is_empty() {
                    manager.emit("downloads-progress", &updates);
                    if ticks.is_multiple_of(10) {
                        manager.persist();
                    }
                }
            }
        });
    }
}

/// Resets segments where earlier progress can't be reused. Returns whether the part file starts empty.
fn reset_segments(rec: &mut DownloadRecord, part_path: &Path) -> bool {
    if !rec.resumable {
        rec.segments = vec![Segment::new(0, rec.total_size.unwrap_or(u64::MAX))];
        return true;
    }
    if rec.segments.iter().any(|s| s.pos > s.start) {
        // Progress without its .part file (deleted by the user?) means starting over.
        let missing = !part_path.exists();
        if missing {
            rec.segments = initial_segments(rec.total_size.unwrap_or(0), rec.connections);
        }
        return missing;
    }
    true
}

/// Fetches all segments over parallel connections into `part_path`. Returns `Ok` once every
/// segment is complete or the run was cancelled, otherwise the most relevant worker error.
async fn run_workers(
    download: &Arc<Download>,
    client: &Client,
    headers: &HeaderMap,
    url: &str,
    cipher: Option<mega::Cipher>,
    part_path: &Path,
    cancel: &CancellationToken,
) -> Result<()> {
    let (resumable, total, connections, fresh) = {
        let mut rec = lock(&download.rec);
        let fresh = reset_segments(&mut rec, part_path);
        (rec.resumable, rec.total_size, rec.connections, fresh)
    };
    let file = open_part(part_path, total.filter(|_| resumable), fresh)
        .map_err(|e| util::fatal(format!("Could not open {}: {e}", part_path.display())))?;

    let transfer = Arc::new(Transfer {
        download: download.clone(),
        client: client.clone(),
        headers: headers.clone(),
        url: url.to_owned(),
        resumable,
        total,
        file: Arc::new(file),
        cipher,
        cancel: cancel.clone(),
    });
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..if resumable { connections.max(1) } else { 1 } {
        workers.spawn(transfer.clone().worker());
    }
    let last_err = join_workers(&mut workers).await;
    drop(transfer); // closes the file so it can be renamed

    let complete = lock(&download.rec).segments.iter().all(|s| s.pos >= s.end);
    if complete || cancel.is_cancelled() {
        return Ok(());
    }
    Err(last_err.unwrap_or_else(|| anyhow!("The download stopped before finishing")))
}

/// `a/b/name.ext`, or `a/b/name (n).ext` for n > 0.
fn numbered(path: &str, n: usize) -> String {
    if n == 0 {
        return path.to_string();
    }
    let (dir, name) = path.rsplit_once('/').map_or(("", path), |(d, f)| (d, f));
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let name = format!("{stem} ({n}){ext}");
    if dir.is_empty() { name } else { format!("{dir}/{name}") }
}

fn part_file(path: &Path) -> PathBuf {
    let mut part = path.as_os_str().to_owned();
    part.push(".part");
    PathBuf::from(part)
}

/// Downloads the files of a MEGA folder through one NordVPN server; each worker fetches one
/// whole file at a time. `segments[i]` (offsets within the folder's total) tracks `folder[i]`.
struct FolderJob {
    download: Arc<Download>,
    client: Client,
    folder: String,
    keys: HashMap<String, [u8; 32]>,
    root_dir: PathBuf,
    /// The pasted link, recorded in each file's Mark of the Web.
    source_url: String,
    cancel: CancellationToken,
}

impl FolderJob {
    fn path(&self, entry: &FolderEntry) -> PathBuf {
        self.root_dir.join(&entry.path)
    }

    /// Brings the recorded progress in line with the disk: finishes renames interrupted by a
    /// crash, creates empty files, and restarts files whose partial download went missing.
    fn reconcile(&self) -> Result<()> {
        let (entries, segments) = {
            let rec = lock(&self.download.rec);
            (rec.folder.clone(), rec.segments.clone())
        };
        let mut restart = Vec::new();
        for (i, (entry, segment)) in entries.iter().zip(&segments).enumerate() {
            let path = self.path(entry);
            let part = part_file(&path);
            if entry.size == 0 {
                if !path.exists() {
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    File::create(&path).map_err(|e| util::fatal(format!("Could not create {}: {e}", path.display())))?;
                }
            } else if segment.pos >= segment.end {
                if !path.exists() {
                    if part.exists() {
                        fs::rename(&part, &path)?;
                        util::mark_from_internet(&path, &self.source_url);
                    } else {
                        restart.push(i);
                    }
                }
            } else if segment.pos > segment.start && !part.exists() {
                restart.push(i);
            }
        }
        let mut rec = lock(&self.download.rec);
        for i in restart {
            rec.segments[i].pos = rec.segments[i].start;
        }
        Ok(())
    }

    async fn worker(self: Arc<Self>) -> Result<()> {
        while let Some(idx) = self.claim() {
            self.download.active.fetch_add(1, Relaxed);
            let result = with_retries(&self.cancel, || self.position(idx), || self.fetch(idx)).await;
            self.download.active.fetch_sub(1, Relaxed);
            lock(&self.download.rec).segments[idx].busy = false;
            if self.cancel.is_cancelled() {
                return Ok(());
            }
            result?;
        }
        Ok(())
    }

    fn claim(&self) -> Option<usize> {
        let mut rec = lock(&self.download.rec);
        let i = rec.segments.iter().position(|s| !s.busy && s.pos < s.end)?;
        rec.segments[i].busy = true;
        Some(i)
    }

    fn position(&self, idx: usize) -> u64 {
        lock(&self.download.rec).segments[idx].pos
    }

    /// One attempt at fetching file `idx`, continuing from its `.part` file.
    async fn fetch(&self, idx: usize) -> Result<()> {
        let (entry, start, end) = {
            let rec = lock(&self.download.rec);
            (rec.folder[idx].clone(), rec.segments[idx].start, rec.segments[idx].end)
        };
        let done = self.position(idx) - start;
        let Some(key) = self.keys.get(&entry.handle) else {
            return Err(util::fatal(format!("{} is no longer in the MEGA folder", entry.path)));
        };
        let resolved = tokio::select! {
            _ = self.cancel.cancelled() => return Ok(()),
            resolved = mega::resolve_in_folder(&self.client, &self.folder, &entry.handle, key) => resolved?,
        };
        let path = self.path(&entry);
        let part = part_file(&path);
        let file = open_part(&part, None, done == 0)
            .map_err(|e| util::fatal(format!("Could not open {}: {e}", part.display())))?;
        let file = Arc::new(file);

        let mut request = self.client.get(&resolved.url);
        if done > 0 {
            request = request.header(header::RANGE, format!("bytes={done}-"));
        }
        let response = tokio::select! {
            _ = self.cancel.cancelled() => return Ok(()),
            response = request.send() => response?,
        };
        let status = response.status();
        if !status.is_success() {
            return Err(util::http_error(status));
        }
        if done > 0 && status != StatusCode::PARTIAL_CONTENT {
            lock(&self.download.rec).segments[idx].pos = start;
            bail!("MEGA ignored the resume position; restarting {}", entry.path);
        }

        let mut stream = response.bytes_stream();
        let mut buf = Vec::with_capacity(FLUSH_SIZE + (256 << 10));
        loop {
            let next = tokio::select! {
                _ = self.cancel.cancelled() => {
                    self.flush(idx, &file, &resolved.cipher, &mut buf).await?;
                    return Ok(());
                }
                next = stream.next() => next,
            };
            match next {
                Some(Ok(chunk)) => {
                    self.download.received.fetch_add(chunk.len() as u64, Relaxed);
                    buf.extend_from_slice(&chunk);
                    if buf.len() >= FLUSH_SIZE {
                        self.flush(idx, &file, &resolved.cipher, &mut buf).await?;
                    }
                }
                Some(Err(e)) => {
                    self.flush(idx, &file, &resolved.cipher, &mut buf).await?;
                    return Err(e.into());
                }
                None => {
                    self.flush(idx, &file, &resolved.cipher, &mut buf).await?;
                    break;
                }
            }
        }
        if self.position(idx) < end {
            bail!("The connection closed before {} finished", entry.path);
        }
        drop(file);
        fs::rename(&part, &path)
            .map_err(|e| util::fatal(format!("Could not move {} into place: {e}", path.display())))?;
        util::mark_from_internet(&path, &self.source_url);
        Ok(())
    }

    /// Decrypts and writes buffered bytes at the file's current position.
    async fn flush(&self, idx: usize, file: &Arc<File>, cipher: &mega::Cipher, buf: &mut Vec<u8>) -> Result<()> {
        let (start, pos, end) = {
            let rec = lock(&self.download.rec);
            let s = &rec.segments[idx];
            (s.start, s.pos, s.end)
        };
        let len = (buf.len() as u64).min(end - pos) as usize;
        if len > 0 {
            let data = std::mem::take(buf);
            *buf = write_chunk(file.clone(), data, len, pos - start, Some(cipher.clone())).await?;
            lock(&self.download.rec).segments[idx].pos = pos + len as u64;
        }
        buf.clear();
        Ok(())
    }
}

/// Runs `attempt` until it succeeds, retrying dropped connections with backoff. An attempt that
/// moved `position` forward resets the retry budget; fatal and blocked errors return at once.
async fn with_retries<Fut: std::future::Future<Output = Result<()>>>(
    cancel: &CancellationToken,
    position: impl Fn() -> u64,
    mut attempt: impl FnMut() -> Fut,
) -> Result<()> {
    let mut attempts = 0;
    loop {
        let before = position();
        let err = match attempt().await {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if cancel.is_cancelled() || util::is_fatal(&err) || util::is_blocked(&err) {
            return Err(err);
        }
        if position() > before {
            attempts = 0;
        }
        attempts += 1;
        if attempts > MAX_SEGMENT_RETRIES {
            return Err(err);
        }
        let delay = Duration::from_millis(500 << attempts.min(5));
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// Waits for every worker and returns the most relevant error: a fatal one if any.
async fn join_workers(workers: &mut tokio::task::JoinSet<Result<()>>) -> Option<anyhow::Error> {
    let mut last_err: Option<anyhow::Error> = None;
    while let Some(joined) = workers.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                if last_err.as_ref().is_none_or(|prev| !util::is_fatal(prev)) {
                    last_err = Some(e);
                }
            }
            Err(e) => last_err = Some(anyhow!("A download worker crashed: {e}")),
        }
    }
    last_err
}

/// Decrypts (when needed) and writes `data[..len]` at `offset` without blocking the runtime.
async fn write_chunk(
    file: Arc<File>,
    mut data: Vec<u8>,
    len: usize,
    offset: u64,
    cipher: Option<mega::Cipher>,
) -> Result<Vec<u8>> {
    let written = tokio::task::spawn_blocking(move || {
        if let Some(cipher) = &cipher {
            cipher.apply(offset, &mut data[..len]);
        }
        let result = util::write_all_at(&file, &data[..len], offset);
        (data, result)
    })
    .await;
    match written {
        Ok((data, Ok(()))) => Ok(data),
        Ok((_, Err(e))) => Err(util::fatal(format!("Could not write to disk: {e}"))),
        Err(e) => Err(anyhow!("Disk write task failed: {e}")),
    }
}

fn open_part(path: &Path, preallocate: Option<u64>, fresh: bool) -> std::io::Result<File> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if !fresh {
        return OpenOptions::new().write(true).open(path);
    }
    let file = OpenOptions::new().write(true).create(true).truncate(true).open(path)?;
    if let Some(size) = preallocate {
        util::make_sparse(&file);
        file.set_len(size)?;
    }
    Ok(file)
}

/// One attempt at transferring a download through one NordVPN server.
struct Transfer {
    download: Arc<Download>,
    client: Client,
    /// Site session headers (e.g. a gofile cookie) sent with every request.
    headers: HeaderMap,
    url: String,
    resumable: bool,
    total: Option<u64>,
    file: Arc<File>,
    /// Decrypts received bytes in place before they're written (MEGA).
    cipher: Option<mega::Cipher>,
    cancel: CancellationToken,
}

impl Transfer {
    async fn worker(self: Arc<Self>) -> Result<()> {
        while let Some(idx) = self.claim() {
            self.download.active.fetch_add(1, Relaxed);
            let result = self.run_segment(idx).await;
            self.download.active.fetch_sub(1, Relaxed);
            self.release(idx);
            if self.cancel.is_cancelled() {
                return Ok(());
            }
            result?;
        }
        Ok(())
    }

    /// Takes an unclaimed unfinished segment or, failing that, splits the busiest one in half.
    fn claim(&self) -> Option<usize> {
        let mut rec = lock(&self.download.rec);
        let segments = &mut rec.segments;
        if let Some(i) = segments.iter().position(|s| !s.busy && s.remaining() > 0) {
            segments[i].busy = true;
            return Some(i);
        }
        if !self.resumable {
            return None;
        }
        let (i, remaining) = segments
            .iter()
            .enumerate()
            .filter(|(_, s)| s.busy)
            .map(|(i, s)| (i, s.remaining()))
            .max_by_key(|&(_, remaining)| remaining)?;
        if remaining < 2 * MIN_SPLIT {
            return None;
        }
        // The current owner stops at `mid` on its next flush; its buffer (< MIN_SPLIT) can't cross it.
        let mid = segments[i].pos + remaining / 2;
        let mut stolen = Segment::new(mid, segments[i].end);
        stolen.busy = true;
        segments[i].end = mid;
        segments.push(stolen);
        Some(segments.len() - 1)
    }

    fn release(&self, idx: usize) {
        lock(&self.download.rec).segments[idx].busy = false;
    }

    fn position(&self, idx: usize) -> (u64, u64) {
        let rec = lock(&self.download.rec);
        (rec.segments[idx].pos, rec.segments[idx].end)
    }

    async fn run_segment(&self, idx: usize) -> Result<()> {
        with_retries(&self.cancel, || self.position(idx).0, || self.fetch(idx)).await
    }

    async fn fetch(&self, idx: usize) -> Result<()> {
        if !self.resumable {
            // Without range support every attempt starts from the beginning.
            let mut rec = lock(&self.download.rec);
            rec.segments[idx].pos = rec.segments[idx].start;
        }
        let (pos, end) = self.position(idx);
        if pos >= end {
            return Ok(());
        }
        let mut request = self.client.get(&self.url).headers(self.headers.clone());
        if self.resumable {
            request = request.header(header::RANGE, format!("bytes={pos}-{}", end - 1));
        }
        let response = tokio::select! {
            _ = self.cancel.cancelled() => return Ok(()),
            response = request.send() => response?,
        };
        self.check_response(&response, pos)?;

        let mut stream = response.bytes_stream();
        let mut buf = Vec::with_capacity(FLUSH_SIZE + (256 << 10));
        loop {
            let next = tokio::select! {
                _ = self.cancel.cancelled() => {
                    self.flush(idx, &mut buf).await?;
                    return Ok(());
                }
                next = stream.next() => next,
            };
            match next {
                Some(Ok(chunk)) => {
                    self.download.received.fetch_add(chunk.len() as u64, Relaxed);
                    buf.extend_from_slice(&chunk);
                    if buf.len() >= FLUSH_SIZE && self.flush(idx, &mut buf).await? {
                        return Ok(()); // reached the (possibly shrunk) segment end
                    }
                }
                Some(Err(e)) => {
                    self.flush(idx, &mut buf).await?;
                    return Err(e.into());
                }
                None => {
                    self.flush(idx, &mut buf).await?;
                    return self.finish_stream(idx);
                }
            }
        }
    }

    fn check_response(&self, response: &wreq::Response, pos: u64) -> Result<()> {
        let status = response.status();
        if !self.resumable {
            return if status.is_success() { Ok(()) } else { Err(util::http_error(status)) };
        }
        if status != StatusCode::PARTIAL_CONTENT {
            return Err(if status.is_success() {
                util::fatal("The server stopped honouring byte-range requests, so the download can't continue")
            } else {
                util::http_error(status)
            });
        }
        let range = response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .and_then(util::parse_content_range);
        if let Some((start, total)) = range {
            if start != pos {
                return Err(util::fatal(format!("The server returned bytes from {start} instead of {pos}")));
            }
            if let (Some(total), Some(expected)) = (total, self.total) {
                if total != expected {
                    return Err(util::fatal("The file on the server changed since the download started"));
                }
            }
        }
        Ok(())
    }

    fn finish_stream(&self, idx: usize) -> Result<()> {
        let mut rec = lock(&self.download.rec);
        let (pos, end) = (rec.segments[idx].pos, rec.segments[idx].end);
        if end == u64::MAX {
            // Size was unknown: the end of the stream is the end of the file.
            rec.segments[idx].end = pos;
            rec.total_size = Some(pos);
            drop(rec);
            self.file
                .set_len(pos)
                .map_err(|e| util::fatal(format!("Could not write to disk: {e}")))?;
            return Ok(());
        }
        if pos < end {
            bail!("The connection closed before the segment finished");
        }
        Ok(())
    }

    /// Writes buffered bytes at the segment position. Returns true once the segment is complete.
    async fn flush(&self, idx: usize, buf: &mut Vec<u8>) -> Result<bool> {
        // Claim the byte range under the lock first so a concurrent split can't land inside it.
        let (offset, len, done) = {
            let mut rec = lock(&self.download.rec);
            let segment = &mut rec.segments[idx];
            let len = (buf.len() as u64).min(segment.remaining());
            let offset = segment.pos;
            segment.pos += len;
            (offset, len as usize, segment.pos >= segment.end)
        };
        if len > 0 {
            let data = std::mem::take(buf);
            match write_chunk(self.file.clone(), data, len, offset, self.cipher.clone()).await {
                Ok(data) => *buf = data,
                Err(err) => {
                    lock(&self.download.rec).segments[idx].pos = offset;
                    return Err(err);
                }
            }
        }
        buf.clear();
        Ok(done)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    use super::*;

    fn test_data(len: usize) -> Arc<Vec<u8>> {
        let mut x: u32 = 0x1234_5678;
        Arc::new(
            (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x as u8
                })
                .collect(),
        )
    }

    /// Minimal HTTP/1.1 file server. Every `fail_every`-th response is cut off halfway, and each
    /// 64 KiB chunk is followed by `delay_ms` to keep transfers slow enough to observe.
    async fn serve(data: Arc<Vec<u8>>, ranges: bool, fail_every: usize, delay_ms: u64) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = Arc::new(AtomicUsize::new(0));
        tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (data, served) = (data.clone(), served.clone());
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let request = String::from_utf8_lossy(&request).to_lowercase();
                    let range = request
                        .lines()
                        .find_map(|l| l.strip_prefix("range: bytes="))
                        .and_then(|r| {
                            let (a, b) = r.trim().split_once('-')?;
                            Some((a.parse::<usize>().ok()?, b.parse::<usize>().ok()?))
                        });
                    let (partial, start, end) = match range {
                        Some((a, b)) if ranges => (true, a, b.min(data.len() - 1) + 1),
                        _ => (false, 0, data.len()),
                    };
                    let mut head = format!(
                        "HTTP/1.1 {}\r\nContent-Length: {}\r\nConnection: close\r\n",
                        if partial { "206 Partial Content" } else { "200 OK" },
                        end - start
                    );
                    if partial {
                        head += &format!("Content-Range: bytes {start}-{}/{}\r\n", end - 1, data.len());
                    }
                    head += "Content-Disposition: attachment; filename=\"served.bin\"\r\n\r\n";
                    if socket.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let n = served.fetch_add(1, Relaxed) + 1;
                    let cut = fail_every > 0 && n % fail_every == 0 && end - start > 1;
                    let stop = if cut { start + (end - start) / 2 } else { end };
                    for chunk in data[start..stop].chunks(64 << 10) {
                        if socket.write_all(chunk).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                });
            }
        });
        format!("http://{addr}/file.bin")
    }

    fn temp_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("norddm-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    async fn prepare(url: &str, dir: &Path, connections: u32) -> (Arc<Download>, Client) {
        let client = Client::builder().no_proxy().build().unwrap();
        let probe = probe(&client, url, &HeaderMap::new()).await.unwrap();
        let mut rec = DownloadRecord {
            id: "test".into(),
            url: url.into(),
            file_name: probe.file_name.clone(),
            dir: dir.to_string_lossy().into_owned(),
            total_size: None,
            resumable: true,
            connections,
            segments: Vec::new(),
            status: Status::Downloading,
            error: None,
            server: None,
            status_text: None,
            created_at: 0,
            completed_at: None,
            prepared: false,
            auto_name: false,
            is_folder: false,
            folder: Vec::new(),
        };
        rec.apply_probe(&probe);
        (Arc::new(Download::new(rec)), client)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn parallel_download_survives_dropped_connections() {
        let data = test_data(48 << 20);
        let url = serve(data.clone(), true, 3, 1).await;
        let dir = temp_dir();
        let (download, client) = prepare(&url, &dir, 6).await;
        {
            let rec = lock(&download.rec);
            assert!(rec.resumable);
            assert_eq!(rec.total_size, Some(data.len() as u64));
            assert_eq!(rec.file_name, "served.bin");
            assert_eq!(rec.segments.len(), 6);
        }
        let part = lock(&download.rec).part_path();
        run_workers(&download, &client, &HeaderMap::new(), &url, None, &part, &CancellationToken::new()).await.unwrap();

        let rec = lock(&download.rec);
        assert!(rec.segments.iter().all(|s| s.pos == s.end));
        assert!(rec.segments.len() > 6, "idle workers should have split busy segments");
        assert_eq!(rec.downloaded(), data.len() as u64);
        assert!(fs::read(&part).unwrap() == *data, "file content differs");
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resumes_after_cancel_without_corruption() {
        let data = test_data(16 << 20);
        let url = serve(data.clone(), true, 0, 8).await;
        let dir = temp_dir();
        let (download, client) = prepare(&url, &dir, 4).await;
        let part = lock(&download.rec).part_path();

        let cancel = CancellationToken::new();
        let canceller = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            canceller.cancel();
        });
        run_workers(&download, &client, &HeaderMap::new(), &url, None, &part, &cancel).await.unwrap();
        let partial = lock(&download.rec).downloaded();
        assert!(partial > 0 && partial < data.len() as u64, "expected partial progress, got {partial}");

        // Simulate an app restart: busy flags aren't persisted.
        let json = serde_json::to_string(&*lock(&download.rec)).unwrap();
        let restored = Arc::new(Download::new(serde_json::from_str(&json).unwrap()));
        run_workers(&restored, &client, &HeaderMap::new(), &url, None, &part, &CancellationToken::new()).await.unwrap();
        assert_eq!(lock(&restored.rec).downloaded(), data.len() as u64);
        assert!(fs::read(&part).unwrap() == *data, "file content differs after resume");
        fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn server_without_ranges_uses_one_connection_and_retries_from_start() {
        let data = test_data(3 << 20);
        let url = serve(data.clone(), false, 2, 0).await;
        let dir = temp_dir();
        let (download, client) = prepare(&url, &dir, 8).await;
        {
            let rec = lock(&download.rec);
            assert!(!rec.resumable);
            assert_eq!(rec.connections, 1);
        }
        let part = lock(&download.rec).part_path();
        run_workers(&download, &client, &HeaderMap::new(), &url, None, &part, &CancellationToken::new()).await.unwrap();
        assert!(fs::read(&part).unwrap() == *data, "file content differs");
        fs::remove_dir_all(dir).unwrap();
    }

    /// Full engine run through the user's NordVPN account (saved sign-in) and the real internet:
    /// `cargo test live_end_to_end -- --ignored --nocapture`. Optionally set LIVE_URL.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn live_end_to_end() {
        let url = std::env::var("LIVE_URL").unwrap_or_else(|_| {
            "https://file-examples.com/storage/fe9887ce566ae4468955d66/2017/04/file_example_MP4_1920_18MG.mp4".into()
        });
        let dir = temp_dir();
        let manager = DownloadManager::new(Box::new(|_, _| {}), dir.join("data"), dir.clone()).unwrap();
        let started = Instant::now();
        let a = manager.add(AddRequest { url: url.clone(), connections: Some(10) }).unwrap();
        let b = manager.add(AddRequest { url: url.clone(), connections: Some(10) }).unwrap();

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let list = manager.list();
            for d in &list {
                println!(
                    "{:>5.1}s {:<34} {:?} {:>10} bytes  {:?}  via {:?}",
                    started.elapsed().as_secs_f64(),
                    d.record.file_name,
                    d.record.status,
                    d.downloaded,
                    d.record.status_text,
                    d.record.server.as_ref().map(|s| (&s.hostname, &s.exit_ip, &s.city, &s.country))
                );
            }
            let done = list.iter().all(|d| matches!(d.record.status, Status::Completed | Status::Error));
            if done || started.elapsed() > Duration::from_secs(240) {
                break;
            }
        }
        let list = manager.list();
        for d in &list {
            assert_eq!(d.record.status, Status::Completed, "{:?}", d.record.error);
            let size = fs::metadata(d.record.final_path()).unwrap().len();
            assert_eq!(Some(size), d.record.total_size);
        }
        let hosts: HashSet<_> = list.iter().map(|d| d.record.server.as_ref().unwrap().hostname.clone()).collect();
        assert_eq!(hosts.len(), 2, "each download should use its own NordVPN server");
        println!("both finished in {:.1}s", started.elapsed().as_secs_f64());

        for id in [&a.record.id, &b.record.id] {
            manager.remove(id, true).await.unwrap();
        }
        assert!(manager.list().is_empty());

        // Removing a download while it is still connecting/downloading must not hang.
        let c = manager.add(AddRequest { url, connections: Some(10) }).unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        let removing = Instant::now();
        tokio::time::timeout(Duration::from_secs(15), manager.remove(&c.record.id, true)).await.unwrap().unwrap();
        println!("removed an active download in {:?}", removing.elapsed());
        assert!(!c.record.part_path().exists());
        fs::remove_dir_all(dir).unwrap();
    }

    /// A MEGA folder through the saved NordVPN sign-in: downloads part of it, pauses, resumes,
    /// checks decrypted files, fetches one file via the parallel single-file path and compares:
    /// `MEGA_TEST_URL=<folder link> cargo test live_mega_engine -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn live_mega_engine() {
        let url = std::env::var("MEGA_TEST_URL").expect("MEGA_TEST_URL");
        let dir = temp_dir();
        let manager = DownloadManager::new(Box::new(|_, _| {}), dir.join("data"), dir.clone()).unwrap();
        let folder = manager.add(AddRequest { url: url.clone(), connections: Some(8) }).unwrap();
        let id = folder.record.id.clone();
        let wait_downloading = |secs: u64| {
            let manager = manager.clone();
            let id = id.clone();
            async move {
                let started = Instant::now();
                while started.elapsed() < Duration::from_secs(secs) {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    let view = manager.find(&id).unwrap().view();
                    println!(
                        "{:>4.0}s {:?} {} of {:?} bytes, {} active  {:?}",
                        started.elapsed().as_secs_f64(),
                        view.record.status,
                        view.downloaded,
                        view.record.total_size,
                        view.active_connections,
                        view.record.status_text
                    );
                    assert_ne!(view.record.status, Status::Error, "{:?}", view.record.error);
                }
            }
        };
        wait_downloading(60).await;
        manager.pause(&id).await.unwrap();
        let download = manager.find(&id).unwrap();
        let (root, entries, segments, first_pass) = {
            let rec = lock(&download.rec);
            (rec.final_path(), rec.folder.clone(), rec.segments.clone(), rec.downloaded())
        };
        assert!(first_pass > 0, "nothing downloaded");
        let finished: Vec<_> = entries.iter().zip(&segments).filter(|(e, s)| e.size > 0 && s.pos >= s.end).collect();
        println!("paused after {first_pass} bytes; {} files finished", finished.len());
        assert!(!finished.is_empty());
        for (entry, _) in &finished {
            let bytes = fs::read(root.join(&entry.path)).unwrap();
            assert_eq!(bytes.len() as u64, entry.size, "{}", entry.path);
            let image = bytes.starts_with(&[0xFF, 0xD8, 0xFF]) || bytes.starts_with(b"\x89PNG");
            let lower = entry.path.to_lowercase();
            if lower.ends_with(".jpg") || lower.ends_with(".png") || lower.ends_with(".jpeg") {
                assert!(image, "{} doesn't decrypt to an image", entry.path);
            }
        }

        manager.resume(&id).await.unwrap();
        wait_downloading(40).await;
        manager.pause(&id).await.unwrap();
        let second_pass = lock(&download.rec).downloaded();
        println!("after resuming: {second_pass} bytes");
        assert!(second_pass > first_pass, "resume should continue, not restart");

        // The same file through the parallel single-file path must decrypt identically.
        let (entry, _) = finished[0];
        let single_url = format!("{}/file/{}", url.trim_end_matches('/'), entry.handle);
        let single = manager.add(AddRequest { url: single_url, connections: Some(4) }).unwrap();
        let started = Instant::now();
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let view = manager.find(&single.record.id).unwrap().view();
            match view.record.status {
                Status::Completed => break,
                Status::Error => panic!("{:?}", view.record.error),
                _ => assert!(started.elapsed() < Duration::from_secs(120), "single file took too long"),
            }
        }
        let single_rec = lock(&manager.find(&single.record.id).unwrap().rec).clone();
        println!("single file {} via {:?}", single_rec.file_name, single_rec.server.as_ref().map(|s| &s.hostname));
        assert_eq!(
            fs::read(single_rec.final_path()).unwrap(),
            fs::read(root.join(&entry.path)).unwrap(),
            "parallel and folder downloads differ"
        );

        // Removing a running folder closes its NordVPN connections and deletes only partial files.
        let nord_connections = || {
            let out = std::process::Command::new("netstat").args(["-ano", "-p", "tcp"]).output().unwrap();
            let pid = std::process::id().to_string();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| {
                    let cols: Vec<&str> = l.split_whitespace().collect();
                    cols.len() == 5 && cols[2].ends_with(":89") && cols[3] == "ESTABLISHED" && cols[4] == pid
                })
                .count()
        };
        manager.resume(&id).await.unwrap();
        wait_downloading(20).await;
        let before = nord_connections();
        manager.remove(&id, false).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let after = nord_connections();
        println!("NordVPN proxy connections: {before} while downloading, {after} after Remove");
        assert!(before > 0, "expected open NordVPN connections while downloading");
        assert_eq!(after, 0, "Remove should close the download's NordVPN connections");
        assert!(root.join(&entry.path).exists(), "finished files are kept");
        let leftovers = entries.iter().filter(|e| part_file(&root.join(&e.path)).exists()).count();
        assert_eq!(leftovers, 0, "partial files should be removed");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn numbered_paths_avoid_duplicates() {
        assert_eq!(numbered("a/b/x.jpg", 0), "a/b/x.jpg");
        assert_eq!(numbered("a/b/x.jpg", 2), "a/b/x (2).jpg");
        assert_eq!(numbered("x", 1), "x (1)");
    }

    #[test]
    fn display_segments_merge_finished_neighbours() {
        let segments = vec![
            Segment { start: 0, end: 10, pos: 10, busy: false },
            Segment { start: 10, end: 20, pos: 20, busy: false },
            Segment { start: 20, end: 30, pos: 25, busy: false },
            Segment { start: 30, end: 40, pos: 30, busy: false },
        ];
        let shown = display_segments(&segments);
        assert_eq!(shown.len(), 1);
        assert_eq!((shown[0].start, shown[0].end, shown[0].pos), (0, 30, 25));
    }

    #[test]
    fn initial_segments_cover_file_exactly() {
        for (total, n) in [(1u64, 8u32), (5 << 20, 8), ((100 << 20) + 7, 16), (MIN_SPLIT * 3, 32)] {
            let segments = initial_segments(total, n);
            assert_eq!(segments.first().unwrap().start, 0);
            assert_eq!(segments.last().unwrap().end, total);
            assert!(segments.windows(2).all(|w| w[0].end == w[1].start));
            assert!(segments.len() as u64 <= total.div_ceil(MIN_SPLIT));
        }
        assert!(initial_segments(0, 8).is_empty());
    }
}


