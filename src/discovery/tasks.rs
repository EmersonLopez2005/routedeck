//! Read-only discovery of RouteDeck-managed systemd tasks
//! (`/etc/systemd/system/routedeck-task-*.timer` + `.service`).

use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

pub const UNIT_DIR: &str = "/etc/systemd/system";
pub const TASK_PREFIX: &str = "routedeck-task-";

pub fn service_path(name: &str) -> String {
    format!("{}{}{}.service", UNIT_DIR, TASK_PREFIX, name)
}

pub fn timer_path(name: &str) -> String {
    format!("{}{}{}.timer", UNIT_DIR, TASK_PREFIX, name)
}

pub fn unit_name(name: &str) -> String {
    format!("{}{}.timer", TASK_PREFIX, name)
}

/// List all RouteDeck-managed tasks (live) or sample data (mock).
pub fn tasks(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::tasks();
    }

    // next-run times from `systemctl list-timers` (one call for all timers)
    let mut next_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Ok(o) = util::exec(&util::argv(&[
        "systemctl", "list-timers", "--all", "--no-pager", "--no-legend",
    ])) {
        for line in o.stdout.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 3 {
                continue;
            }
            // find the token that is one of our timer units
            if let Some(idx) = f.iter().position(|t| {
                t.starts_with(TASK_PREFIX) && t.ends_with(".timer")
            }) {
                if idx >= 2 {
                    let next = format!("{} {}", f[0], f[1]);
                    next_map.insert(f[idx].to_string(), next);
                }
            }
        }
    }

    let mut items = vec![];
    if let Ok(rd) = std::fs::read_dir(UNIT_DIR) {
        for e in rd.flatten() {
            let fname = e.file_name().to_string_lossy().to_string();
            if !(fname.starts_with(TASK_PREFIX) && fname.ends_with(".timer")) {
                continue;
            }
            let name = fname
                .trim_start_matches(TASK_PREFIX)
                .trim_end_matches(".timer")
                .to_string();
            let timer_txt = std::fs::read_to_string(e.path()).unwrap_or_default();
            let svc_txt = std::fs::read_to_string(service_path(&name)).unwrap_or_default();
            let on_calendar = timer_txt
                .lines()
                .find_map(|l| l.strip_prefix("OnCalendar="))
                .unwrap_or("")
                .trim()
                .to_string();
            let exec = svc_txt
                .lines()
                .find_map(|l| l.strip_prefix("ExecStart="))
                .unwrap_or("")
                .trim()
                .to_string();
            let unit = unit_name(&name);
            let enabled = util::exec(&util::argv(&["systemctl", "is-enabled", &unit]))
                .map(|o| o.stdout.trim().to_string())
                .unwrap_or_else(|_| "unknown".into());
            let active = util::exec(&util::argv(&["systemctl", "is-active", &unit]))
                .map(|o| o.stdout.trim().to_string())
                .unwrap_or_else(|_| "unknown".into());
            let kind = if exec.contains("reboot") { "reboot" } else { "command" };
            items.push(json!({
                "name": name,
                "kind": kind,
                "on_calendar": on_calendar,
                "exec": exec,
                "unit": unit,
                "enabled": enabled,
                "active": active,
                "next": next_map.get(&unit).cloned().unwrap_or_default(),
            }));
        }
    }
    items.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    json!({ "tasks": items, "unit_dir": UNIT_DIR })
}
