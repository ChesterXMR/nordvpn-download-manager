//! Segmented download engine.
//!
//! A file is split into byte-range segments fetched in parallel, one connection per worker, all
//! through the NordVPN proxy client chosen for that download. There is no direct-connection
//! fallback. When a worker finishes early it steals half of the largest remaining segment, so all
//! connections stay busy until the very end. Progress is persisted, so downloads resume across
//! restarts (on a freshly chosen server).

use std::{
    collections::HashSet,
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
    browser,
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
}

impl DownloadRecord {
    fn downloaded(&self) -> u64 {
        self.segments.iter().map(|s| s.pos - s.start).sum()
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
        let record = lock(&self.rec).clone();
        DownloadView {
            downloaded: record.downloaded(),
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
        // A provisional name from the URL; replaced by the server's file name once the link is probed.
        let name = Url::parse(&url)
            .ok()
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
        let (status, part, final_path) = {
            let rec = lock(&download.rec);
            (rec.status, rec.part_path(), rec.final_path())
        };
        if status != Status::Completed {
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
        let (url, prepared) = {
            let rec = lock(&download.rec);
            (rec.url.clone(), rec.prepared)
        };
        self.set_status(download, Status::Connecting, Some("Inspecting the link…".into()));
        // Site-specific preparation may replace the pasted link (a gofile page link becomes the
        // file's direct address) and produce headers every connection must send.
        let (url, headers) = tokio::select! {
            _ = cancel.cancelled() => return Ok(Outcome::Cancelled),
            prepared = sites::prepare(client, &url) => prepared?,
        };
        if !prepared {
            let probe = tokio::select! {
                _ = cancel.cancelled() => return Ok(Outcome::Cancelled),
                probe = probe(client, &url, &headers) => probe?,
            };
            let (id, dir, auto_name) = {
                let rec = lock(&download.rec);
                (rec.id.clone(), rec.dir.clone(), rec.auto_name)
            };
            let taken = if auto_name { self.names_in(&dir, &id) } else { HashSet::new() };
            let mut rec = lock(&download.rec);
            if auto_name {
                rec.file_name = util::unique_name(Path::new(&dir), &probe.file_name, &taken, true);
                rec.auto_name = false;
            }
            rec.apply_probe(&probe);
        }

        let part_path = lock(&download.rec).part_path();
        self.set_status(download, Status::Downloading, None);
        run_workers(download, client, &headers, &url, &part_path, cancel).await?;
        if cancel.is_cancelled() {
            return Ok(Outcome::Cancelled);
        }
        self.finalize(download, &part_path)?;
        Ok(Outcome::Completed)
    }

    fn finalize(&self, download: &Arc<Download>, part_path: &Path) -> Result<()> {
        let mut rec = lock(&download.rec);
        let dir = PathBuf::from(&rec.dir);
        let name = util::unique_name(&dir, &rec.file_name, &HashSet::new(), false);
        fs::rename(part_path, dir.join(&name))
            .map_err(|e| util::fatal(format!("Could not move the finished file into place: {e}")))?;
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
                        segments: rec.segments.clone(),
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
        cancel: cancel.clone(),
    });
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..if resumable { connections.max(1) } else { 1 } {
        workers.spawn(transfer.clone().worker());
    }
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
    drop(transfer); // closes the file so it can be renamed

    let complete = lock(&download.rec).segments.iter().all(|s| s.pos >= s.end);
    if complete || cancel.is_cancelled() {
        return Ok(());
    }
    Err(last_err.unwrap_or_else(|| anyhow!("The download stopped before finishing")))
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
        let mut attempts = 0;
        loop {
            let before = self.position(idx).0;
            let err = match self.fetch(idx).await {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };
            if self.cancel.is_cancelled() || util::is_fatal(&err) || util::is_blocked(&err) {
                return Err(err);
            }
            if self.position(idx).0 > before {
                attempts = 0;
            }
            attempts += 1;
            if attempts > MAX_SEGMENT_RETRIES {
                return Err(err);
            }
            let delay = Duration::from_millis(500 << attempts.min(5));
            tokio::select! {
                _ = self.cancel.cancelled() => return Ok(()),
                _ = tokio::time::sleep(delay) => {}
            }
        }
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
            let file = self.file.clone();
            let data = std::mem::take(buf);
            let written = tokio::task::spawn_blocking(move || {
                let result = util::write_all_at(&file, &data[..len], offset);
                (data, result)
            })
            .await;
            let failure = match written {
                Ok((data, Ok(()))) => {
                    *buf = data;
                    None
                }
                Ok((_, Err(e))) => Some(util::fatal(format!("Could not write to disk: {e}"))),
                Err(e) => Some(anyhow!("Disk write task failed: {e}")),
            };
            if let Some(err) = failure {
                lock(&self.download.rec).segments[idx].pos = offset;
                return Err(err);
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
        run_workers(&download, &client, &HeaderMap::new(), &url, &part, &CancellationToken::new()).await.unwrap();

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
        run_workers(&download, &client, &HeaderMap::new(), &url, &part, &cancel).await.unwrap();
        let partial = lock(&download.rec).downloaded();
        assert!(partial > 0 && partial < data.len() as u64, "expected partial progress, got {partial}");

        // Simulate an app restart: busy flags aren't persisted.
        let json = serde_json::to_string(&*lock(&download.rec)).unwrap();
        let restored = Arc::new(Download::new(serde_json::from_str(&json).unwrap()));
        run_workers(&restored, &client, &HeaderMap::new(), &url, &part, &CancellationToken::new()).await.unwrap();
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
        run_workers(&download, &client, &HeaderMap::new(), &url, &part, &CancellationToken::new()).await.unwrap();
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


