use std::{
    collections::HashSet,
    fmt,
    fs::File,
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::anyhow;
use percent_encoding::percent_decode_str;
use wreq::{
    header::{HeaderMap, CONTENT_DISPOSITION},
    StatusCode,
};

/// An error that retrying (or switching NordVPN server) will not fix.
#[derive(Debug)]
pub struct Fatal(pub String);

impl fmt::Display for Fatal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Fatal {}

pub fn fatal(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fatal(msg.into()))
}

pub fn is_fatal(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| cause.is::<Fatal>())
}

/// The site refused this particular NordVPN server (bot check, IP block). Another server may work,
/// so the download switches server straight away instead of retrying.
#[derive(Debug)]
pub struct Blocked(pub String);

impl fmt::Display for Blocked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Blocked {}

pub fn blocked(msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Blocked(msg.into()))
}

pub fn is_blocked(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| cause.is::<Blocked>())
}

pub fn http_error(status: StatusCode) -> anyhow::Error {
    let msg = format!("Server responded with HTTP {status}");
    match status.as_u16() {
        407 => fatal("NordVPN rejected the proxy credentials (HTTP 407). Check your service credentials in Settings."),
        403 => blocked(format!("The site refused this NordVPN server (HTTP {status})")),
        408 | 425 | 429 => anyhow!(msg),
        400..=499 => fatal(msg),
        _ => anyhow!(msg),
    }
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Parses `bytes <start>-<end>/<total|*>` into `(start, total)`.
pub fn parse_content_range(value: &str) -> Option<(u64, Option<u64>)> {
    let rest = value.trim().strip_prefix("bytes")?.trim();
    let (range, total) = rest.split_once('/')?;
    let (start, _end) = range.split_once('-')?;
    let start = start.trim().parse().ok()?;
    let total = total.trim().parse().ok();
    Some((start, total))
}

pub fn sanitize_filename(name: &str) -> String {
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_control() || r#"<>:"/\|?*"#.contains(c) { '_' } else { c })
        .collect();
    let mut cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    if cleaned.chars().count() > 200 {
        cleaned = cleaned.chars().take(200).collect();
    }
    let stem = cleaned.split('.').next().unwrap_or_default().to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        cleaned.insert(0, '_');
    }
    if cleaned.is_empty() {
        "download".into()
    } else {
        cleaned
    }
}

pub fn filename_from_headers(headers: &HeaderMap) -> Option<String> {
    let value = String::from_utf8_lossy(headers.get(CONTENT_DISPOSITION)?.as_bytes()).into_owned();
    let params: Vec<&str> = value.split(';').map(str::trim).collect();
    // RFC 5987 `filename*=UTF-8''...` takes precedence over plain `filename=`.
    for param in &params {
        if let Some(rest) = strip_prefix_ignore_case(param, "filename*=") {
            let rest = rest.trim_matches('"');
            let encoded = rest.splitn(3, '\'').nth(2).unwrap_or(rest);
            let decoded = percent_decode_str(encoded).decode_utf8_lossy().into_owned();
            if !decoded.trim().is_empty() {
                return Some(decoded);
            }
        }
    }
    for param in &params {
        if let Some(rest) = strip_prefix_ignore_case(param, "filename=") {
            let name = rest.trim().trim_matches('"').to_string();
            if !name.trim().is_empty() {
                return Some(name);
            }
        }
    }
    None
}

pub fn filename_from_url(url: &url::Url) -> Option<String> {
    let segment = url.path_segments()?.rfind(|s| !s.is_empty())?;
    let decoded = percent_decode_str(segment).decode_utf8_lossy().into_owned();
    (!decoded.trim().is_empty()).then_some(decoded)
}

fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &s[prefix.len()..])
}

/// Returns `name`, or `name (n).ext`, so that it collides with no existing file, no `.part` file
/// (when `check_part`), and no name in `taken` (lowercased).
pub fn unique_name(dir: &Path, name: &str, taken: &HashSet<String>, check_part: bool) -> String {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (0..)
        .map(|i| if i == 0 { name.to_string() } else { format!("{stem} ({i}){ext}") })
        .find(|candidate| {
            let collides = taken.contains(&candidate.to_lowercase())
                || dir.join(candidate).exists()
                || (check_part && dir.join(format!("{candidate}.part")).exists());
            !collides
        })
        .expect("unbounded iterator")
}

/// Marks a file sparse so writing a far-away segment first doesn't make NTFS zero-fill the gap.
#[cfg(windows)]
pub fn make_sparse(file: &File) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::{Ioctl::FSCTL_SET_SPARSE, IO::DeviceIoControl};

    let mut returned = 0u32;
    // Best effort: on filesystems without sparse support the file is simply preallocated.
    unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        );
    }
}

#[cfg(not(windows))]
pub fn make_sparse(_file: &File) {}

#[cfg(windows)]
pub fn write_all_at(file: &File, mut data: &[u8], mut offset: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !data.is_empty() {
        let written = file.seek_write(data, offset)?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        data = &data[written..];
        offset += written as u64;
    }
    Ok(())
}

#[cfg(unix)]
pub fn write_all_at(file: &File, data: &[u8], offset: u64) -> io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, data, offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocked_servers_are_switched_not_abandoned() {
        let forbidden = http_error(StatusCode::FORBIDDEN);
        assert!(is_blocked(&forbidden) && !is_fatal(&forbidden));
        let missing = http_error(StatusCode::NOT_FOUND);
        assert!(is_fatal(&missing) && !is_blocked(&missing));
        let busy = http_error(StatusCode::TOO_MANY_REQUESTS);
        assert!(!is_fatal(&busy) && !is_blocked(&busy));
    }
}
