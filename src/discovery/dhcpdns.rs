use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

pub const OUR_SNIPPET: &str = "/etc/dnsmasq.d/routedeck.conf";
pub const OUR_HEADER: &str = "# Managed by RouteDeck — do not edit by hand (regenerated from UI state)\n";

/// Does /etc/dnsmasq.conf include /etc/dnsmasq.d?
fn conf_dir_included() -> Option<String> {
    let text = util::read_file("/etc/dnsmasq.conf");
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') {
            continue;
        }
        if let Some(rest) = l.strip_prefix("conf-dir=") {
            let dir = rest.split(',').next().unwrap_or(rest).trim();
            if dir.starts_with("/etc/dnsmasq.d") || dir == "/etc/dnsmasq.d" {
                return Some(rest.to_string());
            }
            // relative paths are relative to /etc
            if !dir.starts_with('/') && format!("/etc/{}", dir.trim_start_matches("./")).contains("dnsmasq.d") {
                return Some(rest.to_string());
            }
        }
        if let Some(rest) = l.strip_prefix("conf-file=") {
            if rest.contains("dnsmasq.d") {
                return Some(rest.to_string());
            }
        }
    }
    None
}

/// All server= upstreams across main conf + snippets (excluding nothing).
fn collect_upstreams() -> Vec<String> {
    let mut out: Vec<String> = vec![];
    let mut files = vec!["/etc/dnsmasq.conf".to_string()];
    if let Ok(rd) = std::fs::read_dir("/etc/dnsmasq.d") {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().map(|x| x == "conf").unwrap_or(false) {
                files.push(p.to_string_lossy().to_string());
            }
        }
    }
    for f in files {
        for line in util::read_file(&f).lines() {
            let l = line.trim();
            if l.starts_with('#') {
                continue;
            }
            if let Some(rest) = l.strip_prefix("server=") {
                let v = rest.trim().to_string();
                if !v.is_empty() && !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    out
}

/// Parse our snippet into structured bindings.
pub fn parse_our_snippet() -> Value {
    let text = util::read_file(OUR_SNIPPET);
    let exists = !text.is_empty();
    let ours = text.contains("Managed by RouteDeck");
    let mut bindings = vec![];
    let mut upstreams = vec![];
    let mut hosts = vec![];
    let mut scope: Value = json!(null);
    let mut opts = json!({"gateway": "", "dns": [], "domain": ""});
    for line in text.lines() {
        let l = line.trim();
        if l.starts_with('#') || l.is_empty() {
            continue;
        }
        if let Some(rest) = l.strip_prefix("dhcp-host=") {
            // dhcp-host=mac,ip,name[,lease_time]
            let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
            bindings.push(json!({
                "mac": parts.first().cloned().unwrap_or(""),
                "ip": parts.get(1).cloned().unwrap_or(""),
                "name": parts.get(2).cloned().unwrap_or(""),
            }));
        } else if let Some(rest) = l.strip_prefix("server=") {
            upstreams.push(rest.trim().to_string());
        } else if let Some(rest) = l.strip_prefix("dhcp-range=") {
            // dhcp-range=start,end[,netmask][,lease]
            let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
            if parts.len() >= 2 {
                let netmask = if parts.len() >= 3 && parts[2].contains('.') {
                    parts[2].to_string()
                } else {
                    String::new()
                };
                let lease = parts
                    .iter()
                    .rev()
                    .find(|p| p.chars().any(|c| c.is_ascii_alphabetic()))
                    .cloned()
                    .unwrap_or("");
                scope = json!({
                    "start": parts[0], "end": parts[1],
                    "netmask": netmask, "lease": lease,
                });
            }
        } else if let Some(rest) = l.strip_prefix("dhcp-option=") {
            let parts: Vec<&str> = rest.split(',').map(|s| s.trim()).collect();
            match parts.first().copied() {
                Some("3") | Some("option:router") => {
                    if let Some(o) = opts.as_object_mut() {
                        o["gateway"] = json!(parts.get(1).copied().unwrap_or(""));
                    }
                }
                Some("6") | Some("option:dns-server") => {
                    if let Some(o) = opts.as_object_mut() {
                        o["dns"] = json!(parts[1..].to_vec());
                    }
                }
                Some("15") | Some("option:domain-name") => {
                    if let Some(o) = opts.as_object_mut() {
                        o["domain"] = json!(parts.get(1).copied().unwrap_or(""));
                    }
                }
                _ => {}
            }
        } else if let Some(rest) = l.strip_prefix("address=/") {
            // address=/name/ip
            if let Some((name, ip)) = rest.trim_end_matches('/').split_once('/') {
                hosts.push(json!({"name": name, "ip": ip}));
            }
        }
    }
    json!({
        "path": OUR_SNIPPET,
        "exists": exists,
        "ours": ours,
        "bindings": bindings,
        "upstreams": upstreams,
        "scope": scope,
        "options": opts,
        "hosts": hosts,
        "content": text,
    })
}

/// dhcp-range declared in OTHER config files (not ours) — conflict detection.
/// Returns [{file, line}].
pub fn foreign_dhcp_ranges(mode: Mode) -> Vec<Value> {
    if mode == Mode::Mock {
        return vec![
            json!({"file": "/etc/dnsmasq.conf", "line": "dhcp-range=192.168.2.50,192.168.2.150,12h"}),
        ];
    }
    let mut out = vec![];
    let mut files = vec!["/etc/dnsmasq.conf".to_string()];
    if let Ok(rd) = std::fs::read_dir("/etc/dnsmasq.d") {
        for e in rd.flatten() {
            files.push(e.path().to_string_lossy().to_string());
        }
    }
    for f in files {
        if f == OUR_SNIPPET {
            continue;
        }
        for line in util::read_file(&f).lines() {
            let l = line.trim();
            if l.starts_with('#') || l.is_empty() {
                continue;
            }
            if l.starts_with("dhcp-range=") {
                out.push(json!({"file": f, "line": l}));
            }
        }
    }
    out
}

fn parse_leases() -> Vec<Value> {
    let candidates = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/dnsmasq/dnsmasq.leases",
        "/run/dnsmasq.leases",
    ];
    for p in candidates {
        let text = util::read_file(p);
        if text.is_empty() {
            continue;
        }
        let now = util::now_ts();
        let mut out = vec![];
        for line in text.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            let exp: u64 = f[2].parse().unwrap_or(0);
            out.push(json!({
                "mac": f[0],
                "ip": f[1],
                "name": f[2.min(2)].to_string().replace('\u{0}', ""), // placeholder, fixed below
                "lease_id": f.get(3).cloned().unwrap_or(""),
                "expires_ts": exp,
                "remaining_secs": exp.saturating_sub(now),
                "src": p,
            }));
            // dnsmasq lease format: <expiry> <mac> <ip> <hostname> <client-id>
            // Actually: "expiry mac ip hostname clientid" — expiry FIRST.
            if let Ok(e0) = f[0].parse::<u64>() {
                let last = out.last_mut().unwrap();
                *last = json!({
                    "expires_ts": e0,
                    "mac": f.get(1).unwrap_or(&""),
                    "ip": f.get(2).unwrap_or(&""),
                    "name": f.get(3).unwrap_or(&""),
                    "lease_id": f.get(4).cloned().unwrap_or(""),
                    "remaining_secs": e0.saturating_sub(now),
                    "src": p,
                });
            }
        }
        return out;
    }
    vec![]
}

/// DNS view: resolv.conf + NM + dnsmasq upstreams.
pub fn dns_view(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return json!({
            "resolv_nameservers": ["127.0.0.1"],
            "resolv_is_stub": false,
            "resolv_path": "/etc/resolv.conf",
            "dnsmasq_upstreams": ["223.5.5.5", "119.29.29.29"],
            "source": "dnsmasq",
            "nm_dns": [],
        });
    }
    let target = std::fs::read_link("/etc/resolv.conf")
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let text = util::read_file("/etc/resolv.conf");
    let ns: Vec<String> = text
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver").map(|v| v.trim().to_string()))
        .collect();
    let upstreams = collect_upstreams();
    json!({
        "resolv_nameservers": ns,
        "resolv_path": "/etc/resolv.conf",
        "resolv_target": target,
        "resolv_is_stub": target.contains("stub") || target.contains("systemd"),
        "dnsmasq_upstreams": upstreams,
        "source": if !upstreams.is_empty() { "dnsmasq" } else { "resolvconf" },
        "nm_dns": [],
    })
}

pub fn bundle(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::dhcp();
    }

    let dnsmasq_present = util::has_bin("dnsmasq");
    let dnsmasq_running = util::exec(&util::argv(&["systemctl", "is-active", "dnsmasq"]))
        .map(|o| o.stdout.trim() == "active")
        .unwrap_or(false);

    let mut conf_files = vec!["/etc/dnsmasq.conf".to_string()];
    if let Ok(rd) = std::fs::read_dir("/etc/dnsmasq.d") {
        for e in rd.flatten() {
            conf_files.push(e.path().to_string_lossy().to_string());
        }
    }
    conf_files.retain(|f| std::path::Path::new(f).exists());

    let leases = if dnsmasq_running || dnsmasq_present {
        parse_leases()
    } else {
        vec![]
    };

    // NM ICS (ipv4.method shared) — active connections only
    let mut ics = vec![];
    if crate::discovery::nm::summary(mode)["running"] == true {
        for c in crate::discovery::nm::connections(mode) {
            // detail fetch for active ones only: cheap check via device non-empty
            if c["device"].as_str().unwrap_or("").is_empty() {
                continue;
            }
            let uuid = c["uuid"].as_str().unwrap_or("");
            let d = crate::discovery::nm::connection_detail(mode, uuid);
            let keys = &d["keys"];
            if keys["ipv4.method"].as_str().unwrap_or("") == "shared" {
                ics.push(json!({
                    "name": c["name"],
                    "device": c["device"],
                    "addresses": keys["ipv4.addresses"],
                    "gateway": keys["ipv4.gateway"],
                }));
            }
        }
    }

    json!({
        "dnsmasq": {
            "present": dnsmasq_present,
            "running": dnsmasq_running,
            "conf_files": conf_files,
            "conf_dir_included": conf_dir_included().map(|s| json!(s)).unwrap_or(json!(null)),
            "our_snippet": parse_our_snippet(),
            "upstreams": collect_upstreams(),
            "leases": leases,
            "lease_count": leases.len(),
        },
        "nm_ics": ics,
        "foreign_ranges": foreign_dhcp_ranges(mode),
        "kea": {"present": std::path::Path::new("/etc/kea").exists()},
        "isc": {"present": std::path::Path::new("/etc/dhcp/dhcpd.conf").exists()},
        "dns": dns_view(mode),
        "backend": if dnsmasq_present && dnsmasq_running {
            "dnsmasq"
        } else if !ics.is_empty() {
            "nm-ics"
        } else {
            "none"
        },
    })
}
