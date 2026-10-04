//! Read-only online update check: compare local version with the version
//! published on GitHub (raw Cargo.toml of `main`). Never mutates anything.

use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

pub const REPO_RAW: &str = "https://raw.githubusercontent.com/EmersonLopez2005/routedeck/main";

pub fn current_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Download URL of the release binary for a given version.
pub fn binary_url(ver: &str) -> String {
    format!("{}/dist/routedeck-v{}-linux-x64/routedeck", REPO_RAW, ver)
}

/// Parse `version = "x.y.z"` (first occurrence — the [package] section).
fn parse_version(toml: &str) -> Option<String> {
    for line in toml.lines() {
        let l = line.trim();
        if let Some(rest) = l.strip_prefix("version") {
            let rest = rest.trim_start();
            if let Some(v) = rest.strip_prefix('=') {
                let v = v.trim().trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Semver-ish compare: a > b ?
pub fn ver_greater(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .map(|p| {
                p.chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u64>()
                    .unwrap_or(0)
            })
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

/// Check whether a newer version is published. Returns:
/// `{ current, latest, has_update, url }` or `{ current, error }`.
pub fn check(mode: Mode) -> Value {
    let current = current_version();
    if mode == Mode::Mock {
        // demo: pretend the next patch version is published
        let mut parts: Vec<String> = current.split('.').map(|s| s.to_string()).collect();
        if let Some(last) = parts.last_mut() {
            *last = (last.parse::<u64>().unwrap_or(0) + 1).to_string();
        }
        let latest = parts.join(".");
        return json!({
            "current": current,
            "latest": latest,
            "has_update": true,
            "url": binary_url(&latest),
            "mock": true,
        });
    }

    if !util::has_bin("curl") {
        return json!({
            "current": current,
            "latest": null,
            "has_update": false,
            "error": "未找到 curl，无法检查更新",
        });
    }
    let manifest = format!("{}/Cargo.toml", REPO_RAW);
    let out = match util::exec(&util::argv(&[
        "curl", "-fsSL", "--connect-timeout", "10", "--max-time", "20", &manifest,
    ])) {
        Ok(o) => o,
        Err(e) => {
            return json!({
                "current": current,
                "latest": null,
                "has_update": false,
                "error": format!("网络错误: {}", e),
            });
        }
    };
    if !out.ok() {
        return json!({
            "current": current,
            "latest": null,
            "has_update": false,
            "error": format!("获取版本信息失败: {}", out.stderr.trim()),
        });
    }
    match parse_version(&out.stdout) {
        Some(latest) => json!({
            "current": current,
            "latest": latest,
            "has_update": ver_greater(&latest, &current),
            "url": binary_url(&latest),
        }),
        None => json!({
            "current": current,
            "latest": null,
            "has_update": false,
            "error": "远端 Cargo.toml 中未解析到版本号",
        }),
    }
}
