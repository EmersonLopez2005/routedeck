use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

/// Parse `nft -j list ruleset` into a display + summary structure.
fn parse_nft_json(root: &Value) -> (Vec<Value>, Value) {
    let mut tables: Vec<Value> = vec![];
    let mut summary = json!({
        "masquerade": false,
        "masquerade_ifaces": [],
        "forward_policy": "unknown",
        "dnat_count": 0,
        "rule_count": 0,
        "chain_count": 0,
    });
    let Some(items) = root.get("nftables").and_then(|a| a.as_array()) else {
        return (tables, summary);
    };

    // collect table metadata
    let mut tmap: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    let mut chains: Vec<(String, String, Value)> = vec![]; // (table_key, chain_name, chain_obj)
    let mut rules: Vec<(String, String, Value)> = vec![]; // (table_key, chain_name, rule_obj)

    for it in items {
        if let Some(t) = it.get("table") {
            let fam = t.get("family").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let name = t.get("name").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            tmap.entry(format!("{}|{}", fam, name)).or_insert_with(|| {
                json!({"family": fam, "name": name, "chains": [], "rule_total": 0})
            });
        } else if let Some(c) = it.get("chain") {
            let fam = c.get("family").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let tname = c.get("table").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let cname = c.get("name").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            chains.push((format!("{}|{}", fam, tname), cname, c.clone()));
        } else if let Some(r) = it.get("rule") {
            let fam = r.get("family").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let tname = r.get("table").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            let cname = r.get("chain").and_then(|x| x.as_str()).unwrap_or("?").to_string();
            rules.push((format!("{}|{}", fam, tname), cname, r.clone()));
        }
    }

    summary["rule_count"] = json!(rules.len());
    summary["chain_count"] = json!(chains.len());

    // summarize interesting things across ALL rules (read-only)
    let mut m_ifaces: Vec<String> = vec![];
    let mut dnat_count = 0;
    for (_, _, r) in &rules {
        let exprs = r.get("expr").and_then(|e| e.as_array()).cloned().unwrap_or_default();
        if expr_contains(&exprs, "masquerade") {
            // find oif/iif near it
            if let Some(ifn) = exprs_iif(&exprs) {
                if !m_ifaces.contains(&ifn) {
                    m_ifaces.push(ifn);
                }
            }
        }
        if expr_contains(&exprs, "dnat") {
            dnat_count += 1;
        }
        if exprs
            .iter()
            .any(|e| e.get("counter").is_some())
        {
            // noop
        }
    }
    summary["masquerade"] = json!(!m_ifaces.is_empty());
    summary["masquerade_ifaces"] = json!(m_ifaces);
    summary["dnat_count"] = json!(dnat_count);

    // forward policy from filter tables (chain with hook forward)
    for (_, cname, c) in &chains {
        let hook = c.get("hook").and_then(|h| h.get("name")).and_then(|x| x.as_str());
        if hook == Some("forward") {
            let pol = c.get("policy").and_then(|x| x.as_str()).unwrap_or("accept");
            summary["forward_policy"] = json!(pol);
            let _ = cname;
            break;
        }
    }

    // build per-table structure
    for (key, chain_name, c) in &chains {
        let fam = c.get("family").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        let tname = c.get("table").and_then(|x| x.as_str()).unwrap_or("?").to_string();
        let rule_total = rules.iter().filter(|(k, cn, _)| k == key && cn == chain_name).count();
        if let Some(t) = tmap.get_mut(key) {
            let arr = t["chains"].as_array_mut().unwrap();
            arr.push(json!({
                "name": chain_name,
                "type": c.get("type").and_then(|x| x.as_str()).unwrap_or(""),
                "hook": c.get("hook").and_then(|h| h.get("name")).and_then(|x| x.as_str()).unwrap_or(""),
                "priority": c.get("hook").and_then(|h| h.get("priority")).map(|p| match p {
                    Value::Number(n) => json!(n),
                    Value::String(s) => json!(s),
                    _ => json!(null),
                }).unwrap_or(json!(null)),
                "policy": c.get("policy").and_then(|x| x.as_str()).unwrap_or(""),
                "rule_total": rule_total,
            }));
            t["rule_total"] = json!(t["rule_total"].as_u64().unwrap_or(0) + rule_total as u64);
            let _ = fam;
            let _ = tname;
        }
    }

    for (_, v) in tmap {
        tables.push(v);
    }
    (tables, summary)
}

fn expr_contains(exprs: &[Value], key: &str) -> bool {
    exprs.iter().any(|e| e.get(key).is_some())
}

fn exprs_iif(exprs: &[Value]) -> Option<String> {
    for e in exprs {
        if let Some(m) = e.get("meta") {
            if m.get("key").and_then(|x| x.as_str()) == Some("oifname") {
                if let Some(v) = m.get("value").and_then(|x| x.as_str()) {
                    return Some(v.to_string());
                }
            }
        }
        if let Some(mt) = e.get("match") {
            let left = mt.get("left").and_then(|l| l.get("meta"));
            if left.and_then(|m| m.get("key")).and_then(|x| x.as_str()) == Some("oifname") {
                if let Some(v) = mt.get("right").and_then(|x| x.as_str()) {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

/// Extract our managed rules from `table inet routedeck`.
/// We store self-describing comments: "rd:<id> | <人类可读描述>".
fn managed_rules(root: &Value) -> Vec<Value> {
    let mut out = vec![];
    let Some(items) = root.get("nftables").and_then(|a| a.as_array()) else {
        return out;
    };
    for it in items {
        if let Some(r) = it.get("rule") {
            if r.get("family").and_then(|x| x.as_str()) != Some("inet")
                || r.get("table").and_then(|x| x.as_str()) != Some("routedeck")
            {
                continue;
            }
            let handle = r.get("handle").and_then(|x| x.as_u64()).unwrap_or(0);
            let chain = r.get("chain").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mut comment = String::new();
            let mut rd_id = String::new();
            if let Some(exprs) = r.get("expr").and_then(|e| e.as_array()) {
                for e in exprs {
                    if let Some(c) = e.get("comment").and_then(|c| c.get("value")).and_then(|x| x.as_str()) {
                        comment = c.to_string();
                        if let Some(rest) = c.strip_prefix("rd:") {
                            rd_id = rest.split('|').next().unwrap_or("").trim().to_string();
                        }
                    }
                }
            }
            let desc = comment
                .split('|')
                .nth(1)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| comment.clone());
            out.push(json!({
                "handle": handle,
                "chain": chain,
                "id": rd_id,
                "comment": comment,
                "desc": if desc.is_empty() { comment.clone() } else { desc },
            }));
        }
    }
    out
}

pub fn bundle(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::nat();
    }

    let nft_present = util::has_bin("nft");
    if nft_present {
        let json_out = util::exec(&util::argv(&["nft", "-j", "list", "ruleset"])).ok();
        let text_out = util::exec(&util::argv(&["nft", "list", "ruleset"])).ok();
        let root: Value = json_out
            .as_ref()
            .and_then(|o| serde_json::from_str(&o.stdout).ok())
            .unwrap_or(json!({"nftables": []}));
        let (tables, summary) = parse_nft_json(&root);
        let managed = managed_rules(&root);
        let table_exists = tables
            .iter()
            .any(|t| t["name"] == "routedeck" && t["family"] == "inet");
        return json!({
            "backend": "nft",
            "nft": {
                "present": true,
                "ruleset_text": text_out.map(|o| o.stdout).unwrap_or_default(),
                "tables": tables,
                "managed": {
                    "available": true,
                    "table_exists": table_exists,
                    "table": "inet routedeck",
                    "rules": managed,
                }
            },
            "summary": summary,
            "iptables": {"present": util::has_bin("iptables")},
        });
    }

    // fallback: iptables-save (read-only display only; managed writes unavailable)
    let nat_text = util::exec(&util::argv(&["iptables-save", "-t", "nat"]))
        .map(|o| o.stdout)
        .unwrap_or_default();
    let filter_text = util::exec(&util::argv(&["iptables-save", "-t", "filter"]))
        .map(|o| o.stdout)
        .unwrap_or_default();
    let present = !nat_text.is_empty() || !filter_text.is_empty();
    json!({
        "backend": if present { "iptables" } else { "none" },
        "nft": {"present": false, "managed": {"available": false, "table_exists": false, "rules": []}},
        "iptables": {
            "present": present,
            "nat_text": nat_text,
            "filter_text": filter_text,
        },
        "summary": {
            "masquerade": nat_text.contains("MASQUERADE"),
            "masquerade_ifaces": [],
            "forward_policy": if filter_text.contains("-P FORWARD DROP") { "drop" } else { "accept" },
            "dnat_count": nat_text.matches("DNAT").count(),
        }
    })
}
