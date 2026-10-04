use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Raw result of an external command execution.
#[derive(Debug, Clone, Serialize)]
pub struct CmdOut {
    pub argv: Vec<String>,
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOut {
    pub fn ok(&self) -> bool {
        self.code == 0
    }
}

/// Execute a command, capturing output. Never panics; I/O errors are returned.
pub fn exec(argv: &[String]) -> Result<CmdOut> {
    if argv.is_empty() {
        bail!("empty command");
    }
    let out = Command::new(&argv[0])
        .args(&argv[1..])
        .output()
        .with_context(|| format!("spawn failed: {}", argv[0]))?;
    Ok(CmdOut {
        argv: argv.to_vec(),
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Execute a command; bail with stderr when exit code != 0.
pub fn exec_ok(argv: &[String]) -> Result<String> {
    let out = exec(argv)?;
    if !out.ok() {
        bail!(
            "`{}` failed (code {}): {}",
            argv.join(" "),
            out.code,
            out.stderr.trim()
        );
    }
    Ok(out.stdout)
}

/// Convenience: build a String argv from &str items.
pub fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Check whether a binary exists in PATH.
pub fn has_bin(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

pub fn now_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Wall-clock millis for log entries.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// RFC3339-ish local timestamp for filenames / audit display.
pub fn ts_human() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

pub fn ts_file() -> String {
    chrono::Local::now().format("%Y%m%d-%H%M%S").to_string()
}

/// Generate a short unique id: base36(ms) + counter-ish suffix.
pub fn short_id(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let rand = {
        // 32 bits of entropy from the OS
        let mut buf = [0u8; 4];
        if let Ok(f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = (&f).read_exact(&mut buf);
        }
        if buf == [0; 4] {
            (now_ms() as u32) ^ 0x9e37_79b9
        } else {
            u32::from_le_bytes(buf)
        }
    };
    format!("{}{:x}{:03x}", prefix, now_ms() % 0xffffff, (rand ^ n as u32) % 0xfff)
}

/// Sanitize a filesystem path into a filename fragment.
pub fn sanitize_filename(path: &str) -> String {
    path.trim_start_matches('/')
        .replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], "_")
}

/// Read a file as string ("" when missing).
pub fn read_file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

/// Read first N bytes of a file as string.
pub fn read_file_capped(path: &str, cap: usize) -> String {
    match std::fs::read(path) {
        Ok(b) => String::from_utf8_lossy(&b[..b.len().min(cap)]).into_owned(),
        Err(_) => String::new(),
    }
}

pub fn file_exists(path: &str) -> bool {
    PathBuf::from(path).exists()
}
