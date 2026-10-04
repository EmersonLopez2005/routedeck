use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

/// Split an nmcli terse line on unescaped colons.
/// nmcli escapes `\:` and `\\` when `--escape yes` (default in -t mode... we pass explicitly).
pub fn split_terse(line: &str) -> Vec<String> {
    let mut out = vec![];
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                if let Some(&n) = chars.peek() {
                    if n == ':' || n == '\\' {
                        cur.push(n);
                        chars.next();
                        continue;
                    }
                }
                cur.push('\\');
            }
            ':' => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn nmcli(mode: Mode, args: &[&str]) -> Option<util::CmdOut> {
    if mode == Mode::Mock {
        return None;
    }
    let mut argv = vec!["nmcli", "--escape", "yes"];
    argv.extend_from_slice(args);
    util::exec(&util::argv(&argv)).ok()
}

pub fn summary(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return json!({"present": true, "running": true, "version": "nmcli tool, version 1.52.0"});
    }
    let present = util::has_bin("nmcli");
    let mut running = false;
    if let Some(o) = nmcli(mode, &["-t", "general"]) {
        for line in o.stdout.lines() {
            if let Some(v) = line.strip_prefix("RUNNING:") {
                running = v == "yes";
            }
        }
    }
    let version = nmcli(mode, &["--version"])
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    json!({ "present": present, "running": running, "version": version })
}

/// Devices: `nmcli -t -f DEVICE,TYPE,STATE,CONNECTION device status`
pub fn devices(mode: Mode) -> Vec<Value> {
    if mode == Mode::Mock {
        return crate::discovery::mock::nm_devices();
    }
    let Some(o) = nmcli(mode, &["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
    else {
        return vec![];
    };
    o.stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f = split_terse(l);
            json!({
                "device": f.first().cloned().unwrap_or_default(),
                "type": f.get(1).cloned().unwrap_or_default(),
                "state": f.get(2).cloned().unwrap_or_default(),
                "connection": f.get(3).cloned().unwrap_or_default(),
            })
        })
        .collect()
}

/// Connections: `nmcli -t -f NAME,UUID,TYPE,DEVICE connection show`
pub fn connections(mode: Mode) -> Vec<Value> {
    if mode == Mode::Mock {
        return crate::discovery::mock::nm_connections();
    }
    let Some(o) = nmcli(mode, &["-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show"])
    else {
        return vec![];
    };
    o.stdout
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f = split_terse(l);
            json!({
                "name": f.first().cloned().unwrap_or_default(),
                "uuid": f.get(1).cloned().unwrap_or_default(),
                "type": f.get(2).cloned().unwrap_or_default(),
                "device": f.get(3).cloned().unwrap_or_default(),
            })
        })
        .collect()
}

/// Full property map of one connection (`nmcli -t connection show <ref>`).
pub fn connection_detail(mode: Mode, conn_ref: &str) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::nm_connection_detail(conn_ref);
    }
    let Some(o) = nmcli(mode, &["-t", "connection", "show", conn_ref]) else {
        return json!({"error": "nmcli 不可用或连接不存在", "keys": {}});
    };
    if !o.ok() {
        return json!({"error": o.stderr.trim(), "keys": {}});
    }
    let mut map = serde_json::Map::new();
    for line in o.stdout.lines() {
        if let Some((k, v)) = line.split_once(':') {
            // nmcli terse output is already unescaped for values? It escapes ':' as '\:'
            // split once then unescape
            let k = k.replace("\\:", ":").replace("\\\\", "\\");
            let v = v.replace("\\:", ":").replace("\\\\", "\\");
            map.insert(k, json!(v));
        }
    }
    json!({ "keys": map })
}

/// Bundle everything the interfaces page needs.
pub fn bundle(mode: Mode) -> Value {
    json!({
        "nm": summary(mode),
        "devices": devices(mode),
        "connections": connections(mode),
    })
}
