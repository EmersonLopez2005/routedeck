//! Read-only discovery. Every function in this layer runs ONLY inspection
//! commands (`ip`, `nmcli`, `nft`, `ss`, `docker`, ...) and reads files.
//! Nothing here ever mutates system configuration.

pub mod dhcpdns;
pub mod docker;
pub mod host;
pub mod mock;
pub mod nat;
pub mod net;
pub mod nm;
pub mod packages;
pub mod services;
pub mod tasks;

use crate::state::Mode;
use serde_json::{json, Value};
use crate::util;

/// Run a command in live mode, or return None in mock mode.
pub fn live_argv(mode: Mode, argv: &[&str]) -> Option<util::CmdOut> {
    if mode == Mode::Mock {
        return None;
    }
    util::exec(&util::argv(argv)).ok()
}

/// `ip -j ...` helper (live mode only).
pub fn ip_json(mode: Mode, args: &[&str]) -> Option<Value> {
    let mut argv = vec!["ip", "-j"];
    argv.extend_from_slice(args);
    let out = live_argv(mode, &argv)?;
    if !out.ok() {
        return None;
    }
    serde_json::from_str(&out.stdout).ok()
}

/// Extract a string field from a JSON object.
pub fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

/// Extract an integer that iproute2 may emit as number or string.
pub fn num(v: &Value, key: &str) -> Option<u64> {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_u64(),
        Some(Value::String(st)) => st.parse().ok(),
        _ => None,
    }
}

/// Top-level detection snapshot — the "install-time, read-only" report.
/// This is what `install.sh` prints before touching anything (it touches nothing).
pub fn detection(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return mock::detection();
    }

    let ip_ok = util::has_bin("ip");
    let nft_ok = util::has_bin("nft");
    let ipt_ok = util::has_bin("iptables");
    let nm_out = util::exec(&util::argv(&["nmcli", "-t", "general"])).ok();
    let nm_present = nm_out.is_some() || util::has_bin("nmcli");
    let mut nm_running = false;
    let mut nm_version = String::new();
    if let Some(o) = &nm_out {
        for line in o.stdout.lines() {
            if let Some(v) = line.strip_prefix("RUNNING:") {
                nm_running = v == "yes";
            }
        }
    }
    if let Some(o) = util::exec(&util::argv(&["nmcli", "--version"])).ok() {
        nm_version = o.stdout.trim().to_string();
    }

    let unit = |name: &str| -> String {
        if mode == Mode::Mock {
            return "inactive".into();
        }
        util::exec(&util::argv(&["systemctl", "is-active", name]))
            .map(|o| o.stdout.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    };

    let ifupdown = std::path::Path::new("/etc/network/interfaces").exists();
    let networkd_running = unit("systemd-networkd") == "active";
    let dnsmasq_present = util::has_bin("dnsmasq");
    let dnsmasq_running = unit("dnsmasq") == "active";
    let kea = std::path::Path::new("/etc/kea").exists();
    let isc = unit("isc-dhcp-server") == "active" || util::has_bin("isc-dhcp-server");
    let docker_bin = util::has_bin("docker");
    let docker_version = if docker_bin {
        util::exec(&util::argv(&["docker", "version", "--format", "{{.Server.Version}}"]))
            .map(|o| if o.ok() { o.stdout.trim().to_string() } else { String::new() })
            .unwrap_or_default()
    } else {
        String::new()
    };
    let hostapd = util::has_bin("hostapd") || unit("hostapd") == "active";
    let pppd = util::has_bin("pppd");
    let nft_running = unit("nftables") == "active";

    // nft rules count (read-only)
    let nft_rules = if nft_ok {
        util::exec(&util::argv(&["nft", "-j", "list", "ruleset"]))
            .ok()
            .and_then(|o| serde_json::from_str::<Value>(&o.stdout).ok())
            .map(|v| {
                v.get("nftables")
                    .and_then(|a| a.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter(|e| e.get("rule").is_some())
                            .count()
                    })
                    .unwrap_or(0)
            })
            .unwrap_or(0)
    } else {
        0
    };

    let kernel = util::read_file("/proc/sys/kernel/osrelease").trim().to_string();

    json!({
        "ts": util::ts_human(),
        "mode": mode.as_str(),
        "kernel": kernel,
        "backends": {
            "iproute2": {"present": ip_ok},
            "network_manager": {"present": nm_present, "running": nm_running, "version": nm_version},
            "networkd": {"present": util::has_bin("networkd") || ifupdown || true, "running": networkd_running},
            "ifupdown": {"present": ifupdown, "interfaces_file": ifupdown},
            "nftables": {"present": nft_ok, "running": nft_running, "rules": nft_rules},
            "iptables": {"present": ipt_ok},
            "dnsmasq": {"present": dnsmasq_present, "running": dnsmasq_running},
            "kea": {"present": kea},
            "isc_dhcp": {"present": isc},
            "docker": {"present": docker_bin && !docker_version.is_empty(), "version": docker_version},
            "hostapd": {"present": hostapd},
            "pppd": {"present": pppd}
        },
        "promise": "本次检测为只读：未修改任何网络配置、未安装任何软件包。"
    })
}

/// Full status payload for the dashboard.
pub fn status(mode: Mode) -> Value {
    let h = host::host_info(mode);
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "mode": mode.as_str(),
        "hostname": h["hostname"],
        "os": h["os"],
        "kernel": h["kernel"],
        "uptime_secs": h["uptime_secs"],
        "started_ms": util::now_ms(),
    })
}
