use serde::Serialize;
use sysinfo::System;

use crate::util::format_size;

/// Hard upper limit the UI allows.
pub const MAX_CONNECTIONS: u32 = 32;
/// Beyond this, NordVPN proxies and most origin servers start throttling or refusing a single client.
const SOFT_CAP: u32 = 16;
/// Below this per-connection share, extra connections mostly add TLS handshake overhead.
const TARGET_SEGMENT: u64 = 4 << 20;
/// Write buffer plus TLS and socket buffers per connection (conservative).
const PER_CONNECTION_MEMORY: u64 = 8 << 20;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Recommendation {
    pub connections: u32,
    pub max: u32,
    pub cores: u32,
    pub available_memory_mb: u64,
    pub reasons: Vec<String>,
}

pub fn recommend(size: Option<u64>, resumable: bool, other_active: usize) -> Recommendation {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(4);
    let mut sys = System::new();
    sys.refresh_memory();
    let available = sys.available_memory();
    let available_memory_mb = available / (1 << 20);
    let mut reasons = Vec::new();

    if !resumable {
        reasons.push(
            "The server doesn't support ranged requests, so the file can only be fetched over one connection."
                .into(),
        );
        return Recommendation { connections: 1, max: 1, cores, available_memory_mb, reasons };
    }

    // Each connection is TLS-inside-TLS through the Nord proxy, so decryption cost scales with streams.
    let cpu_budget = (cores + 2).min(MAX_CONNECTIONS);
    reasons.push(format!(
        "{cores} logical CPU cores can decrypt about {cpu_budget} TLS-over-proxy streams without becoming the bottleneck."
    ));
    let mut n = cpu_budget;

    if n > SOFT_CAP {
        n = SOFT_CAP;
        reasons.push(format!(
            "Capped at {SOFT_CAP}: beyond that, NordVPN proxy servers and most web servers start throttling extra connections from one client."
        ));
    }

    let memory_budget = (available / PER_CONNECTION_MEMORY).clamp(1, u32::MAX as u64) as u32;
    if memory_budget < n {
        n = memory_budget;
        reasons.push(format!(
            "Only {} of RAM is free, which limits buffering to {n} connections.",
            format_size(available)
        ));
    }

    if other_active > 0 {
        let share = (cpu_budget / (other_active as u32 + 1)).max(2);
        if share < n {
            n = share;
            reasons.push(format!(
                "{other_active} other download(s) are running, so the connection budget is shared between them."
            ));
        }
    }

    match size {
        Some(size) => {
            let cap = size.div_ceil(TARGET_SEGMENT).clamp(1, u32::MAX as u64) as u32;
            if cap < n {
                n = cap;
                reasons.push(format!(
                    "The file is only {}; more than {cap} connection(s) would mostly add handshake overhead.",
                    format_size(size)
                ));
            }
        }
        None => reasons.push(
            "The file size isn't known yet; small files automatically use fewer connections.".into(),
        ),
    }

    Recommendation {
        connections: n.max(1),
        max: MAX_CONNECTIONS,
        cores,
        available_memory_mb,
        reasons,
    }
}
