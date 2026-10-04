use crate::backend::Plan;
use crate::util;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Mode {
    /// Real host: discovery runs actual commands, writes are applied.
    Live,
    /// Fixture host: everything is simulated (used on non-Linux dev machines).
    Mock,
}

impl Mode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Mode::Live => "live",
            Mode::Mock => "mock",
        }
    }
}

/// Previous network/CPU sample used to compute deltas on the next poll.
#[derive(Debug, Clone, Default)]
pub struct NetSample {
    pub ts_ms: u64,
    pub cpu_total: u64,
    pub cpu_idle: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

struct Inner {
    plans: HashMap<String, Plan>,
    last_sample: Option<NetSample>,
}

pub struct AppState {
    pub mode: Mode,
    pub data_dir: PathBuf,
    pub token: Option<String>,
    pub started: Instant,
    inner: Mutex<Inner>,
    plan_seq: AtomicU64,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(mode: Mode, data_dir: PathBuf, token: Option<String>) -> Shared {
        std::fs::create_dir_all(data_dir.join("backups")).ok();
        std::fs::create_dir_all(data_dir.join("runs")).ok();
        Arc::new(AppState {
            mode,
            data_dir,
            token,
            started: Instant::now(),
            inner: Mutex::new(Inner {
                plans: HashMap::new(),
                last_sample: None,
            }),
            plan_seq: AtomicU64::new(1),
        })
    }

    pub fn next_plan_seq(&self) -> u64 {
        self.plan_seq.fetch_add(1, Ordering::Relaxed)
    }

    /// Register a plan; returns its id. Plans expire after 10 minutes.
    pub fn put_plan(&self, mut plan: Plan) -> String {
        if plan.id.is_empty() {
            plan.id = format!("p{:04}", self.next_plan_seq());
        }
        plan.created_ms = util::now_ms();
        let id = plan.id.clone();
        let mut g = self.inner.lock().unwrap();
        // prune expired
        let now = util::now_ms();
        g.plans.retain(|_, p| now.saturating_sub(p.created_ms) < 10 * 60 * 1000);
        g.plans.insert(id.clone(), plan);
        id
    }

    pub fn get_plan(&self, id: &str) -> Option<Plan> {
        self.inner.lock().unwrap().plans.get(id).cloned()
    }

    pub fn drop_plan(&self, id: &str) {
        self.inner.lock().unwrap().plans.remove(id);
    }

    /// Update (or create) the previous sample; returns (rates) when a previous existed.
    pub fn net_sample(&self, rx: u64, tx: u64, cpu_total: u64, cpu_idle: u64) -> Option<(u64, u64, f32)> {
        let mut g = self.inner.lock().unwrap();
        let now = util::now_ms();
        let prev = g.last_sample.clone();
        g.last_sample = Some(NetSample {
            ts_ms: now,
            cpu_total,
            cpu_idle,
            rx_bytes: rx,
            tx_bytes: tx,
        });
        let prev = prev?;
        let dt = now.saturating_sub(prev.ts_ms);
        if dt < 200 {
            return None;
        }
        let secs = dt as f64 / 1000.0;
        let rx_bps = (rx.saturating_sub(prev.rx_bytes) as f64 * 8.0 / secs) as u64;
        let tx_bps = (tx.saturating_sub(prev.tx_bytes) as f64 * 8.0 / secs) as u64;
        let dt_total = cpu_total.saturating_sub(prev.cpu_total);
        let dt_idle = cpu_idle.saturating_sub(prev.cpu_idle);
        let cpu = if dt_total > 0 {
            ((dt_total.saturating_sub(dt_idle)) as f32 / dt_total as f32) * 100.0
        } else {
            0.0
        };
        Some((rx_bps, tx_bps, cpu))
    }

    pub fn last_cpu(&self) -> Option<f32> {
        // cheap: recompute nothing, keep a cached value updated by net_sample callers
        None
    }

    // ---------- audit ----------

    pub fn audit_append(&self, entry: &Value) {
        use std::io::Write;
        let path = self.data_dir.join("audit.jsonl");
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(f, "{}", entry);
        }
    }

    pub fn audit_tail(&self, limit: usize) -> Vec<Value> {
        let path = self.data_dir.join("audit.jsonl");
        let text = std::fs::read_to_string(path).unwrap_or_default();
        let mut items: Vec<Value> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .collect();
        let len = items.len();
        if len > limit {
            items.drain(..len - limit);
        }
        items.reverse(); // newest first
        items
    }

    // ---------- backups ----------

    /// Save file content as a backup. Returns backup id (filename).
    pub fn backup_write(&self, path: &str, content: &[u8], reason: &str) -> String {
        let id = format!("{}_{}_{}", util::ts_file(), util::sanitize_filename(path), util::short_id(""));
        let dir = self.data_dir.join("backups");
        std::fs::create_dir_all(&dir).ok();
        let bpath = dir.join(&id);
        std::fs::write(&bpath, content).ok();
        // index entry
        let idx = self.data_dir.join("backups.json");
        let mut list: Vec<Value> = std::fs::read_to_string(&idx)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        list.push(json!({
            "id": id,
            "path": path,
            "ts": util::ts_human(),
            "size": content.len(),
            "reason": reason,
        }));
        if list.len() > 500 {
            let cut = list.len() - 500;
            list.drain(..cut);
        }
        let _ = std::fs::write(&idx, serde_json::to_string_pretty(&list).unwrap_or_default());
        id
    }

    pub fn backup_read(&self, id: &str) -> Option<Vec<u8>> {
        // reject traversal
        if id.contains('/') || id.contains('\\') || id.contains("..") {
            return None;
        }
        std::fs::read(self.data_dir.join("backups").join(id)).ok()
    }

    pub fn backup_list(&self) -> Vec<Value> {
        let idx = self.data_dir.join("backups.json");
        std::fs::read_to_string(idx)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    /// Persist the first-run detection snapshot (installer also calls this via `detect`).
    pub fn save_detection(&self, report: &Value) {
        let p = self.data_dir.join("detection.json");
        let _ = std::fs::write(p, serde_json::to_string_pretty(report).unwrap_or_default());
    }

    pub fn load_detection(&self) -> Option<Value> {
        let p = self.data_dir.join("detection.json");
        std::fs::read_to_string(p).ok().and_then(|t| serde_json::from_str(&t).ok())
    }
}

/// Auth check helper shared by handlers.
pub fn authorized(state: &AppState, headers: &axum::http::HeaderMap, query_token: Option<&str>) -> bool {
    match &state.token {
        None => true,
        Some(t) => {
            if t.is_empty() {
                return true;
            }
            if let Some(q) = query_token {
                if constant_time_eq(q.as_bytes(), t.as_bytes()) {
                    return true;
                }
            }
            if let Some(h) = headers.get("x-auth-token").and_then(|v| v.to_str().ok()) {
                return constant_time_eq(h.as_bytes(), t.as_bytes());
            }
            // cookie fallback
            if let Some(c) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
                for part in c.split(';') {
                    let part = part.trim();
                    if let Some(v) = part.strip_prefix("rd_token=") {
                        if constant_time_eq(v.as_bytes(), t.as_bytes()) {
                            return true;
                        }
                    }
                }
            }
            false
        }
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// Plan is the only backend type state needs.
