use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

fn proc_meminfo() -> (u64, u64) {
    // (total_kb, available_kb)
    let text = util::read_file("/proc/meminfo");
    let mut total = 0u64;
    let mut avail = 0u64;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("MemTotal:") {
            total = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("MemAvailable:") {
            avail = v.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
        }
    }
    (total, avail)
}

/// Public wrapper for (total, idle) jiffies of the aggregate `cpu` line.
pub fn proc_stat_cpu_pub() -> (u64, u64) {
    proc_stat_cpu()
}

fn proc_stat_cpu() -> (u64, u64) {
    // (total, idle) in jiffies
    let text = util::read_file("/proc/stat");
    if let Some(line) = text.lines().next() {
        if let Some(rest) = line.strip_prefix("cpu ") {
            let nums: Vec<u64> = rest
                .split_whitespace()
                .filter_map(|x| x.parse::<u64>().ok())
                .collect();
            if nums.len() >= 4 {
                let total: u64 = nums.iter().sum();
                let idle = nums[3] + nums.get(4).unwrap_or(&0); // idle + iowait
                return (total, idle);
            }
        }
    }
    (0, 0)
}

/// Aggregate rx/tx bytes across non-loopback interfaces from /proc/net/dev.
pub fn net_counters() -> (u64, u64) {
    let text = util::read_file("/proc/net/dev");
    let mut rx = 0u64;
    let mut tx = 0u64;
    for line in text.lines().skip(2) {
        let Some((dev, rest)) = line.split_once(':') else { continue };
        let dev = dev.trim();
        if dev == "lo" {
            continue;
        }
        let nums: Vec<u64> = rest.split_whitespace().filter_map(|x| x.parse().ok()).collect();
        if nums.len() >= 9 {
            rx += nums[0];
            tx += nums[8];
        }
    }
    (rx, tx)
}

pub fn cpu_model() -> String {
    let text = util::read_file("/proc/cpuinfo");
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("model name") {
            return v.trim_start_matches(':').trim().to_string();
        }
        if let Some(v) = line.strip_prefix("Hardware") {
            return v.trim_start_matches(':').trim().to_string();
        }
    }
    "unknown".into()
}

pub fn cpu_cores() -> usize {
    util::read_file("/proc/cpuinfo")
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count()
        .max(1)
}

pub fn loadavg() -> Vec<f64> {
    util::read_file("/proc/loadavg")
        .split_whitespace()
        .take(3)
        .filter_map(|x| x.parse().ok())
        .collect()
}

pub fn uptime_secs() -> u64 {
    util::read_file("/proc/uptime")
        .split_whitespace()
        .next()
        .and_then(|x| x.parse::<f64>().ok())
        .map(|f| f as u64)
        .unwrap_or(0)
}

pub fn hostname() -> String {
    let h = util::read_file("/proc/sys/kernel/hostname").trim().to_string();
    if h.is_empty() {
        "localhost".into()
    } else {
        h
    }
}

pub fn os_pretty() -> String {
    let text = util::read_file("/etc/os-release");
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return v.trim_matches('"').to_string();
        }
    }
    util::read_file("/etc/debian_version").trim().to_string()
}

/// Host snapshot used by the dashboard. In Live mode the CPU percentage and
/// bps rates come from deltas kept in shared state (caller injects them).
pub fn host_info(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return mock_host();
    }
    json!({
        "hostname": hostname(),
        "os": os_pretty(),
        "kernel": util::read_file("/proc/sys/kernel/osrelease").trim().to_string(),
        "uptime_secs": uptime_secs(),
        "cpu_model": cpu_model(),
        "cores": cpu_cores(),
        "mem_total_kb": proc_meminfo().0,
        "mem_avail_kb": proc_meminfo().1,
        "load": loadavg(),
    })
}

fn mock_host() -> Value {
    // deterministic-ish wiggle for demo
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mem_total = 8 * 1024 * 1024 * 1024u64;
    let used_ratio = 0.32 + ((t / 7) % 5) as f64 * 0.01;
    json!({
        "hostname": "soft-router",
        "os": "Debian GNU/Linux 13 (trixie)",
        "kernel": "6.12.45-1",
        "uptime_secs": 86400 * 3 + (t % 3600),
        "cpu_model": "Intel(R) N100 (4C/4T)",
        "cores": 4,
        "mem_total_kb": mem_total / 1024,
        "mem_avail_kb": ((mem_total as f64 * (1.0 - used_ratio)) as u64) / 1024,
        "load": [0.08, 0.12, 0.09],
    })
}

/// CPU busy % (live): needs previous sample. Returns None on first call.
pub fn cpu_pct(mode: Mode, prev: Option<(u64, u64)>) -> Option<f32> {
    if mode == Mode::Mock {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let v = 6.0 + ((t / 900) % 14) as f32;
        return Some(v);
    }
    let (total, idle) = proc_stat_cpu();
    let (pt, pi) = prev?;
    let dt = total.saturating_sub(pt);
    let di = idle.saturating_sub(pi);
    if dt == 0 {
        return Some(0.0);
    }
    Some((dt.saturating_sub(di)) as f32 / dt as f32 * 100.0)
}

/// /proc/net/dev totals (live) or synthetic (mock).
pub fn rx_tx_bytes(mode: Mode) -> (u64, u64) {
    if mode == Mode::Mock {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0) as u64;
        // gentle sawtooth so rates are non-zero
        let rx = 9_000_000_000 + t * 37;
        let tx = 2_500_000_000 + t * 11;
        return (rx, tx);
    }
    net_counters()
}
