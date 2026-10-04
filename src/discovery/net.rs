use super::{ip_json, num, s};
use crate::state::Mode;
use crate::util;
use serde_json::{json, Map, Value};

/// Interface kinds we recognize (ip link `linkinfo.info_kind` or heuristics).
fn kind_of(v: &Value) -> String {
    if let Some(k) = v
        .get("linkinfo")
        .and_then(|li| li.get("info_kind"))
        .and_then(|x| x.as_str())
    {
        return k.to_string();
    }
    let name = s(v, "ifname").unwrap_or("");
    if name.starts_with("ppp") {
        return "ppp".into();
    }
    if name.starts_with("wg") {
        return "wireguard".into();
    }
    if name.starts_with("tun") || name.starts_with("tap") {
        return "tun".into();
    }
    if name == "lo" {
        return "loopback".into();
    }
    "ethernet".into()
}

/// Convert an interface kind into a friendly category for the UI.
pub fn category(kind: &str) -> &'static str {
    match kind {
        "bridge" => "bridge",
        "vlan" => "vlan",
        "bond" => "bond",
        "veth" | "dummy" | "ifb" => "virtual",
        "wireguard" => "vpn",
        "gre" | "sit" | "ip6tnl" | "ipip" | "vti" => "tunnel",
        "ppp" => "ppp",
        "loopback" => "loopback",
        "wlan" | "wireless" | "nl80211" => "wifi",
        _ => "ethernet",
    }
}

pub fn interfaces(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::interfaces();
    }

    let links = ip_json(mode, &["-s", "link", "show"]).unwrap_or(json!([]));
    let addrs = ip_json(mode, &["addr", "show"]).unwrap_or(json!([]));
    let routes = ip_json(mode, &["route", "show"]).unwrap_or(json!([]));
    let neigh = ip_json(mode, &["neigh", "show"]).unwrap_or(json!([]));

    // default route devices (v4)
    let mut default_devs: Vec<String> = vec![];
    if let Some(arr) = routes.as_array() {
        for r in arr {
            let dst = s(r, "dst").unwrap_or("default");
            if dst == "default" || dst == "0.0.0.0/0" {
                if let Some(d) = s(r, "dev") {
                    if !default_devs.contains(&d.to_string()) {
                        default_devs.push(d.to_string());
                    }
                }
            }
        }
    }

    // addresses by ifindex
    let mut addr_map: std::collections::HashMap<i64, (Vec<String>, Vec<String>)> = Default::default();
    if let Some(arr) = addrs.as_array() {
        for iface in arr {
            let idx = num(iface, "ifindex").unwrap_or(0) as i64;
            let mut v4 = vec![];
            let mut v6 = vec![];
            if let Some(list) = iface.get("addr_info").and_then(|a| a.as_array()) {
                for a in list {
                    let fam = s(a, "family").unwrap_or("");
                    let local = s(a, "local").unwrap_or("");
                    let plen = num(a, "prefixlen").unwrap_or(0);
                    if local.is_empty() {
                        continue;
                    }
                    let cidr = format!("{}/{}", local, plen);
                    match fam {
                        "inet" => v4.push(cidr),
                        "inet6" => {
                            // skip link-local for display tidiness? keep but mark
                            v6.push(cidr);
                        }
                        _ => {}
                    }
                }
            }
            addr_map.insert(idx, (v4, v6));
        }
    }

    let mut out: Vec<Value> = vec![];
    if let Some(arr) = links.as_array() {
        for l in arr {
            let idx = num(l, "ifindex").unwrap_or(0);
            let name = s(l, "ifname").unwrap_or("?").to_string();
            let kind = kind_of(l);
            let mut flags: Vec<String> = l
                .get("flags")
                .and_then(|f| f.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            flags.retain(|f| f != "BROADCAST" && f != "MULTICAST" && f != "UP" && f != "LOWER_UP");
            let (v4, v6) = addr_map.get(&(idx as i64)).cloned().unwrap_or_default();

            // stats (ip -s link) — stats64 or stats
            let stats = l.get("stats64").or(l.get("stats"));
            let (rx, tx) = match stats {
                Some(st) => (
                    st.get("rx").and_then(|x| x.get("bytes")).and_then(|x| x.as_u64()).unwrap_or(0),
                    st.get("tx").and_then(|x| x.get("bytes")).and_then(|x| x.as_u64()).unwrap_or(0),
                ),
                None => (0, 0),
            };

            let parent = l
                .get("link")
                .and_then(|x| x.as_str())
                .map(String::from)
                .or_else(|| {
                    l.get("linkinfo")
                        .and_then(|li| li.get("info_data"))
                        .and_then(|d| d.get("link"))
                        .and_then(|x| x.as_str())
                        .map(String::from)
                });
            let vlan_id = l
                .get("linkinfo")
                .and_then(|li| li.get("info_data"))
                .and_then(|d| d.get("id"))
                .and_then(|x| x.as_u64());

            let operstate = s(l, "operstate").unwrap_or("unknown").to_string();
            out.push(json!({
                "name": name,
                "ifindex": idx,
                "kind": kind,
                "category": category(&kind),
                "operstate": operstate,
                "up": flags.iter().any(|f| f == "UP") || operstate == "UP",
                "mac": s(l, "address").unwrap_or(""),
                "mtu": num(l, "mtu").unwrap_or(0),
                "flags": flags,
                "parent": parent,
                "vlan_id": vlan_id,
                "addr4": v4,
                "addr6": v6,
                "rx_bytes": rx,
                "tx_bytes": tx,
                "is_default": default_devs.contains(&name),
                "qdisc": s(l, "qdisc").unwrap_or(""),
            }));
        }
    }

    // neighbor count per device (client inventory snippet)
    let mut neigh_map: std::collections::HashMap<String, u32> = Default::default();
    if let Some(arr) = neigh.as_array() {
        for n in arr {
            if let Some(d) = s(n, "dev") {
                *neigh_map.entry(d.to_string()).or_insert(0) += 1;
            }
        }
    }
    for it in out.iter_mut() {
        let n = it.get("name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        if let Some(c) = neigh_map.get(&n) {
            it["neighbors"] = json!(c);
        } else {
            it["neighbors"] = json!(0);
        }
    }

    json!({ "interfaces": out, "default_devs": default_devs })
}

pub fn routes(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::routes();
    }
    let raw = ip_json(mode, &["route", "show", "table", "all"]).unwrap_or(json!([]));
    let rules = ip_json(mode, &["rule", "show"]).unwrap_or(json!([]));

    let mut out = vec![];
    if let Some(arr) = raw.as_array() {
        for r in arr {
            let dst = s(r, "dst").unwrap_or("default").to_string();
            let table = r
                .get("table")
                .map(|t| match t {
                    Value::Number(n) => n.to_string(),
                    Value::String(st) => st.clone(),
                    _ => "main".into(),
                })
                .unwrap_or_else(|| "main".into());
            out.push(json!({
                "dst": dst,
                "gateway": s(r, "gateway").unwrap_or(""),
                "dev": s(r, "dev").unwrap_or(""),
                "prefsrc": s(r, "prefsrc").unwrap_or(""),
                "table": table,
                "protocol": s(r, "protocol").unwrap_or(""),
                "scope": s(r, "scope").unwrap_or(""),
                "metric": num(r, "metric").unwrap_or(0),
                "type": s(r, "type").unwrap_or(""),
                "src": s(r, "src").unwrap_or(""),
            }));
        }
    }
    // default gw/dev
    let mut gw = String::new();
    let mut dev = String::new();
    for r in &out {
        if r["dst"] == "default" && r["table"] == "main" {
            gw = r["gateway"].as_str().unwrap_or("").to_string();
            dev = r["dev"].as_str().unwrap_or("").to_string();
            break;
        }
    }

    let mut rules_out = vec![];
    if let Some(arr) = rules.as_array() {
        for r in arr {
            let mut m = Map::new();
            m.insert("priority".into(), json!(num(r, "priority").unwrap_or(0)));
            m.insert(
                "table".into(),
                json!(r.get("table").map(|t| match t {
                    Value::Number(n) => n.to_string(),
                    Value::String(st) => st.clone(),
                    _ => "?".into(),
                }).unwrap_or_default()),
            );
            m.insert("action".into(), json!(s(r, "action").unwrap_or("")));
            m.insert("src".into(), json!(s(r, "src").unwrap_or("")));
            rules_out.push(Value::Object(m));
        }
    }

    json!({ "routes": out, "rules": rules_out, "default_gw": gw, "default_dev": dev })
}

/// Simple reverse-path / connectivity probe is intentionally NOT included:
/// discovery stays passive.
pub fn _unused() -> &'static str {
    // keep util import used on all cfgs
    let _ = util::now_ts;
    "x"
}
