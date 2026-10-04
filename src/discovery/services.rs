use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

/// Parse `ss -lntupH` (or -lupH for udp) output lines.
/// Columns: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
fn parse_ss(text: &str) -> Vec<Value> {
    let mut out = vec![];
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 5 {
            continue;
        }
        // f[0] = Netid (tcp/udp), f[1] = state (LISTEN for -l) — with -l output:
        // "tcp LISTEN 0 511 0.0.0.0:22 0.0.0.0:* users:..." — Netid, State, Recv-Q, Send-Q, Local, Peer, [process]
        // For UDP -l: "udp UNCONN 0 0 0.0.0.0:68 0.0.0.0:*"
        let (proto, state, local, peer, process) = if f.len() >= 6 {
            (f[0], f[1], f[4], f[5], f.get(6..).map(|r| r.join(" ")).unwrap_or_default())
        } else {
            (f[0], "", f[3], f[4], f.get(5..).map(|r| r.join(" ")).unwrap_or_default())
        };
        // extract process name from users:(("name",pid=N,fd=F))
        let mut proc_name = String::new();
        let mut pid = 0u64;
        if let Some(start) = process.find("users:") {
            let seg = &process[start..];
            if let Some(q1) = seg.find("((\"") {
                let rest = &seg[q1 + 3..];
                if let Some(q2) = rest.find('"') {
                    proc_name = rest[..q2].to_string();
                }
                if let Some(p) = rest.find("pid=") {
                    let r2 = &rest[p + 4..];
                    let digits: String = r2.chars().take_while(|c| c.is_ascii_digit()).collect();
                    pid = digits.parse().unwrap_or(0);
                }
            }
        }
        out.push(json!({
            "proto": proto,
            "state": state,
            "local": local,
            "peer": peer,
            "process": proc_name,
            "pid": pid,
        }));
    }
    out
}

pub fn bundle(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::services();
    }

    let tcp = util::exec(&util::argv(&["ss", "-lntupH"]))
        .map(|o| o.stdout)
        .unwrap_or_default();
    let mut listening = parse_ss(&tcp);
    listening.sort_by(|a, b| {
        a["process"]
            .as_str()
            .unwrap_or("")
            .cmp(b["process"].as_str().unwrap_or(""))
    });

    let key_units = [
        "NetworkManager",
        "systemd-networkd",
        "dnsmasq",
        "nftables",
        "docker",
        "ssh",
        "hostapd",
        "systemd-resolved",
    ];
    let mut units = vec![];
    for u in key_units {
        let state = util::exec(&util::argv(&["systemctl", "is-active", u]))
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_else(|_| "unknown".into());
        units.push(json!({"name": u, "state": state}));
    }

    let running = util::exec(&util::argv(&[
        "systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--no-pager",
    ]))
    .map(|o| o.stdout)
    .unwrap_or_default();
    let mut running_list = vec![];
    for line in running.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 4 {
            running_list.push(json!({
                "unit": f[0],
                "load": f[1],
                "active": f[2],
                "sub": f[3],
                "desc": f[4..].join(" "),
            }));
        }
    }

    // web-ish listeners: everything on common web ports gets flagged for the
    // "已部署的 WebUI 项目" inventory.
    let web_ports = [
        "80", "443", "8000", "8001", "8080", "8081", "8443", "8888", "3000", "3001", "5000",
        "5173", "8889", "9000", "9090", "10000", "16666", "25678", "19999", "8082",
    ];
    let mut web = vec![];
    for l in &listening {
        let local = l["local"].as_str().unwrap_or("");
        let port = local.rsplit(':').next().unwrap_or("");
        if web_ports.contains(&port) {
            web.push(l.clone());
        }
    }

    json!({
        "listening": listening,
        "web_listeners": web,
        "key_units": units,
        "running": running_list,
        "running_count": running_list.len(),
    })
}

#[allow(dead_code)]
fn unused() {}
