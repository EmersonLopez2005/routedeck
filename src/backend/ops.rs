//! Controlled write operations.
//!
//! Every function here ONLY builds a `Plan` — it never executes anything.
//! Execution happens later via apply (with user confirmation in the UI),
//! and every plan carries a full, idempotent undo list captured at plan time.

use super::{sha256_hex, sha256_str, CmdStep, FileStep, Plan, RollbackStep};
use crate::discovery::{dhcpdns, nm as nmd, nat as natd};
use crate::state::{Mode, Shared};
use crate::util;
use serde_json::{json, Value};
use std::collections::BTreeMap;

// ---------- validation helpers ----------

fn valid_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| {
            !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u8>().is_ok()
        })
}

fn valid_cidr(s: &str) -> bool {
    match s.split_once('/') {
        Some((ip, p)) => valid_ipv4(ip) && p.parse::<u8>().map(|n| n <= 32).unwrap_or(false),
        None => false,
    }
}

fn valid_mac(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_port(s: &u64) -> bool {
    *s >= 1 && *s <= 65535
}

fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        && !s.contains("..")
}

fn valid_hostname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn sanitize_comment(s: &str) -> String {
    s.replace(['"', '\n', '\r', '\\'], " ")
}

fn p_str(params: &Value, key: &str) -> Result<String, String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("缺少参数: {}", key))
}

fn p_u64(params: &Value, key: &str) -> Result<u64, String> {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("缺少参数: {}", key))
}

fn p_str_arr(params: &Value, key: &str) -> Vec<String> {
    params
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str()).map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

// ---------- nmcli helpers (live) ----------

/// nmcli terse connection show -> map
fn nm_keys(mode: Mode, conn_ref: &str) -> Result<BTreeMap<String, String>, String> {
    if mode == Mode::Mock {
        let d = crate::discovery::mock::nm_connection_detail(conn_ref);
        let mut m = BTreeMap::new();
        if let Some(obj) = d.get("keys").and_then(|k| k.as_object()) {
            for (k, v) in obj {
                m.insert(k.clone(), v.as_str().unwrap_or("").to_string());
            }
        }
        return Ok(m);
    }
    let out = util::exec(&util::argv(&["nmcli", "-t", "connection", "show", conn_ref]))
        .map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(format!("连接不存在或 nmcli 失败: {}", out.stderr.trim()));
    }
    let mut m = BTreeMap::new();
    for line in out.stdout.lines() {
        if let Some((k, v)) = line.split_once(':') {
            m.insert(
                k.replace("\\:", ":").replace("\\\\", "\\"),
                v.replace("\\:", ":").replace("\\\\", "\\"),
            );
        }
    }
    Ok(m)
}

fn nm_conn_exists(mode: Mode, conn_ref: &str) -> bool {
    if mode == Mode::Mock {
        return true;
    }
    util::exec(&util::argv(&["nmcli", "-t", "connection", "show", conn_ref]))
        .map(|o| o.ok())
        .unwrap_or(false)
}

/// Which connection currently carries the default route device? (disconnect warning)
fn connection_carries_default(mode: Mode, conn_ref: &str) -> bool {
    if mode == Mode::Mock {
        return conn_ref.contains("WAN") || conn_ref.contains("1111") || conn_ref.contains("2222");
    }
    let conns = nmd::connections(mode);
    let mut dev = String::new();
    for c in &conns {
        let r = c["uuid"].as_str().unwrap_or("");
        let n = c["name"].as_str().unwrap_or("");
        if r == conn_ref || n == conn_ref {
            dev = c["device"].as_str().unwrap_or("").to_string();
            break;
        }
    }
    if dev.is_empty() {
        return false;
    }
    let routes = crate::discovery::net::routes(mode);
    routes["default_dev"].as_str().unwrap_or("") == dev
}

/// Does the active SSH session likely ride this connection? (best-effort:
/// compare default route dev with the source interface of sshd connections)
fn warn_disconnect(plan: &mut Plan, mode: Mode, conn_ref: &str) {
    if connection_carries_default(mode, conn_ref) {
        plan.may_disconnect = true;
        plan.warnings.push(
            "⚠ 该连接承载默认路由：应用后如果参数有误，管理连接可能中断。请确认参数正确；如有第二个入口（WAN2/控制台），保持其可用。".into(),
        );
    } else {
        plan.warnings.push(
            "若你正通过该接口访问本面板（SSH/Web），修改后连接可能中断。".into(),
        );
    }
}

// ---------- operations ----------

/// op: nm.apply_ip — static or DHCP addressing for an NM connection.
pub fn nm_apply_ip(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    let method = p_str(params, "method")?; // manual | auto
    if !["manual", "auto"].contains(&method.as_str()) {
        return Err("method 必须是 manual 或 auto".into());
    }
    let addresses = p_str_arr(params, "addresses");
    let gateway = params.get("gateway").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let dns = p_str_arr(params, "dns");

    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    if method == "manual" {
        if addresses.is_empty() {
            return Err("静态模式至少需要一个地址（CIDR，如 192.168.1.1/24）".into());
        }
        for a in &addresses {
            if !valid_cidr(a) {
                return Err(format!("非法地址: {}（应为 如 192.168.1.1/24）", a));
            }
        }
        if !gateway.is_empty() && !valid_ipv4(&gateway) {
            return Err(format!("非法网关: {}", gateway));
        }
    }
    for d in &dns {
        if !valid_ipv4(d) && !d.contains(':') {
            return Err(format!("非法 DNS: {}", d));
        }
    }

    let before = nm_keys(state.mode, &conn)?;
    let mut plan = Plan::new(
        "nm.apply_ip",
        &format!("修改连接 {} 的 IPv4 配置", conn),
        "high",
    );
    plan.description = format!(
        "方法: {} | 地址: {} | 网关: {} | DNS: {}",
        method,
        if addresses.is_empty() { "-".into() } else { addresses.join(", ") },
        if gateway.is_empty() { "-".into() } else { gateway.clone() },
        if dns.is_empty() { "-".into() } else { dns.join(", ") },
    );

    let mut restore_keys: Vec<(String, String)> = vec![];
    for k in ["ipv4.method", "ipv4.addresses", "ipv4.gateway", "ipv4.dns"] {
        restore_keys.push((k.to_string(), before.get(k).cloned().unwrap_or_default()));
    }

    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.method", &method]),
        desc: format!("设置 {} 的 ipv4.method = {}", conn, method),
    });
    if method == "manual" {
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.addresses", &addresses.join(",")]),
            desc: "设置静态地址".into(),
        });
        if gateway.is_empty() {
            plan.commands.push(CmdStep {
                argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.gateway", ""]),
                desc: "清除网关".into(),
            });
        } else {
            plan.commands.push(CmdStep {
                argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.gateway", &gateway]),
                desc: format!("设置网关 {}", gateway),
            });
        }
    }
    let dns_val = dns.join(",");
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.dns", &dns_val]),
        desc: if dns.is_empty() { "清除 DNS".into() } else { format!("设置 DNS {}", dns_val) },
    });
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重激活连接 {}", conn),
    });

    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: restore_keys,
        desc: format!("还原连接 {} 的 IPv4 属性", conn),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重新激活连接 {}", conn),
    });
    warn_disconnect(&mut plan, state.mode, &conn);
    Ok(plan)
}

/// op: nm.add_route — persistent static route via nmcli (+ipv4.routes).
pub fn nm_add_route(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    let dst = p_str(params, "dst")?;
    let gw = params.get("gw").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    let metric = params.get("metric").and_then(|v| v.as_u64());

    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    // dst: CIDR or "default"
    if dst != "default" && !valid_cidr(&dst) {
        return Err(format!("非法目标网络: {}（CIDR 如 10.0.0.0/8，或 default）", dst));
    }
    if !gw.is_empty() && !valid_ipv4(&gw) {
        return Err(format!("非法下一跳: {}", gw));
    }

    let before = nm_keys(state.mode, &conn)?;
    let old_routes = before.get("ipv4.routes").cloned().unwrap_or_default();

    let mut plan = Plan::new("nm.add_route", "添加静态路由", "medium");
    plan.description = format!("via {} dev {} metric {}", if gw.is_empty() { "(直连)" } else { &gw }, conn, metric.map(|m| m.to_string()).unwrap_or_else(|| "auto".into()));

    let spec = if let Some(m) = metric {
        format!("{},{}", dst, m)
    } else {
        dst.clone()
    };
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "modify", &conn, "+ipv4.routes", &spec]),
        desc: format!("向 {} 添加路由 {}", conn, spec),
    });

    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: vec![("ipv4.routes".into(), old_routes)],
        desc: "还原路由列表".into(),
    });
    Ok(plan)
}

/// op: nm.del_route — remove matching route from connection's ipv4.routes.
pub fn nm_del_route(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    let dst = p_str(params, "dst")?;
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    if dst != "default" && !valid_cidr(&dst) {
        return Err(format!("非法目标网络: {}", dst));
    }
    let before = nm_keys(state.mode, &conn)?;
    let old_routes = before.get("ipv4.routes").cloned().unwrap_or_default();

    let mut plan = Plan::new("nm.del_route", "删除静态路由", "medium");
    plan.description = format!("从 {} 移除路由 {}", conn, dst);
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "modify", &conn, "-ipv4.routes", &dst]),
        desc: format!("从 {} 删除路由 {}", conn, dst),
    });
    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: vec![("ipv4.routes".into(), old_routes)],
        desc: "还原路由列表".into(),
    });
    Ok(plan)
}

/// Ensure our nft table + nat chain exist (idempotent commands, only when missing).
fn nft_ensure_table_chain(plan: &mut Plan, mode: Mode) -> (bool, bool) {
    let nat = natd::bundle(mode);
    let exists = nat["nft"]["managed"]["table_exists"].as_bool().unwrap_or(false);
    let chain_exists = nat["nft"]["tables"]
        .as_array()
        .map(|ts| {
            ts.iter().any(|t| t["name"] == "routedeck"
                && t["chains"]
                    .as_array()
                    .map(|cs| cs.iter().any(|c| c["name"] == "prerouting"))
                    .unwrap_or(false))
        })
        .unwrap_or(false);

    if !exists {
        plan.commands.push(CmdStep {
            argv: util::argv(&["nft", "add", "table", "inet", "routedeck"]),
            desc: "创建托管表 inet routedeck".into(),
        });
    }
    if !chain_exists {
        plan.commands.push(CmdStep {
            argv: vec![
                "nft".into(),
                "add".into(),
                "chain".into(),
                "inet".into(),
                "routedeck".into(),
                "prerouting".into(),
                "{ type nat hook prerouting priority dstnat; policy accept; }".into(),
            ],
            desc: "创建托管链 prerouting (nat)".into(),
        });
    }
    (exists, chain_exists)
}

/// op: nft.add_forward — DNAT port forward in our managed table.
pub fn nft_add_forward(state: &Shared, params: &Value) -> Result<Plan, String> {
    let proto = p_str(params, "proto")?; // tcp | udp
    if !["tcp", "udp"].contains(&proto.as_str()) {
        return Err("proto 必须是 tcp 或 udp".into());
    }
    let wan_if = params.get("wan_if").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !wan_if.is_empty() && !valid_ifname(&wan_if) {
        return Err(format!("非法接口名: {}", wan_if));
    }
    let dst_port = p_u64(params, "dst_port")?;
    if !valid_port(&dst_port) {
        return Err("目标端口必须是 1-65535".into());
    }
    let to_addr = p_str(params, "to_addr")?;
    if !valid_ipv4(&to_addr) {
        return Err(format!("非法内网地址: {}", to_addr));
    }
    let to_port = params.get("to_port").and_then(|v| v.as_u64());
    if let Some(tp) = to_port {
        if !valid_port(&tp) {
            return Err("内网端口必须是 1-65535".into());
        }
    }
    let note = params
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let rd_id = util::short_id("fwd");
    let target = match to_port {
        Some(tp) => format!("{}:{}", to_addr, tp),
        None => to_addr.clone(),
    };
    let where_ = if wan_if.is_empty() { "任意入接口".to_string() } else { wan_if.clone() };
    let desc_line = sanitize_comment(&format!(
        "{}/{} → {} ({}){}",
        dst_port,
        proto,
        target,
        where_,
        if note.is_empty() { String::new() } else { format!(" · {}", note) }
    ));

    let mut plan = Plan::new("nft.add_forward", "添加端口转发", "medium");
    plan.description = format!(
        "外网 {}:{} → 内网 {}{}",
        if wan_if.is_empty() { "*" } else { &wan_if },
        dst_port,
        target,
        if note.is_empty() { String::new() } else { format!("（{}）", note) }
    );
    nft_ensure_table_chain(&mut plan, state.mode);

    let comment = format!("rd:{} | {}", rd_id, desc_line);
    let mut argv = vec![
        "nft".into(),
        "add".into(),
        "rule".into(),
        "inet".into(),
        "routedeck".into(),
        "prerouting".into(),
    ];
    if !wan_if.is_empty() {
        argv.push("iifname".into());
        argv.push(format!("\"{}\"", wan_if));
    }
    argv.push(proto.into());
    argv.push("dport".into());
    argv.push(dst_port.to_string());
    argv.push("dnat".into());
    argv.push("to".into());
    argv.push(target.clone());
    argv.push("comment".into());
    argv.push(format!("\"{}\"", sanitize_comment(&comment)));

    plan.commands.push(CmdStep {
        argv,
        desc: format!("添加 DNAT 规则 {}", desc_line),
    });

    plan.rollback.push(RollbackStep::NftDeleteByComment {
        family: "inet".into(),
        table: "routedeck".into(),
        chain: "prerouting".into(),
        comment: comment.clone(),
        desc: format!("删除规则 {}", desc_line),
    });

    plan.warnings.push(
        "确保系统转发链允许该流量（当前 forward 策略/规则），否则转发不生效；如需，可同时添加放行规则。".into(),
    );
    Ok(plan)
}

/// op: nft.del_rule — delete an rd:-marked rule (managed table or accept rules
/// we appended into a user chain).
pub fn nft_del_rule(state: &Shared, params: &Value) -> Result<Plan, String> {
    let family = p_str(params, "family")?;
    let table = p_str(params, "table")?;
    let chain = p_str(params, "chain")?;
    let id = p_str(params, "id")?; // rd id (not handle)
    if !["inet", "ip", "ip6"].contains(&family.as_str()) {
        return Err(format!("非法 family: {}", family));
    }
    if !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(format!("非法表名: {}", table));
    }
    if !chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err(format!("非法链名: {}", chain));
    }

    let comment = format!("rd:{}", id);
    let rule = find_rd_rule(state.mode, &family, &table, &chain, &comment)?;
    let rule_text = rule["text"].as_str().unwrap_or("").to_string();

    let mut plan = Plan::new("nft.del_rule", "删除规则", "medium");
    plan.description = format!("{} {} {} → {}", family, table, chain, rule_text);

    plan.commands.push(CmdStep {
        argv: util::argv(&["nft", "delete", "rule", &family, &table, &chain, "handle", &rule["handle"].to_string()]),
        desc: "删除 nft 规则".into(),
    });
    // undo: re-add the exact rule text (captured at plan time)
    plan.rollback.push(RollbackStep::Cmd {
        argv: vec!["nft".into(), "add".into(), "rule".into(), family, table, chain, rule_text.clone()],
        desc: format!("恢复规则: {}", rule_text),
    });
    Ok(plan)
}

/// Find an rd: rule in a chain; returns {handle, text}.
/// Live: parse `nft list table <family> <table>` text (lines end with `handle N`).
fn find_rd_rule(mode: Mode, family: &str, table: &str, chain: &str, comment: &str) -> Result<Value, String> {
    if mode == Mode::Mock {
        let nat = crate::discovery::mock::nat();
        let rules = nat["nft"]["managed"]["rules"].as_array().cloned().unwrap_or_default();
        for r in rules {
            if r["comment"].as_str().unwrap_or("").starts_with(comment) {
                return Ok(json!({
                    "handle": r["handle"],
                    "text": format!("{} comment \"{}\"", r["desc"], r["comment"]),
                }));
            }
        }
        return Err("未找到匹配规则".into());
    }
    let out = util::exec(&util::argv(&["nft", "list", "table", family, table]))
        .map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(format!("nft list table 失败: {}", out.stderr.trim()));
    }
    let mut current_chain = String::new();
    for line in out.stdout.lines() {
        let t = line.trim();
        if t.starts_with("chain ") {
            current_chain = t
                .trim_start_matches("chain ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            continue;
        }
        if current_chain != chain {
            continue;
        }
        if !t.contains(comment) {
            continue;
        }
        // extract handle from end
        let handle = t
            .rsplit("handle ")
            .next()
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| "该规则缺少 handle（nft 版本过旧？）".to_string())?;
        let text = t
            .rsplit_once("handle ")
            .map(|(a, _)| a.trim().to_string())
            .unwrap_or_else(|| t.to_string());
        return Ok(json!({"handle": handle, "text": text}));
    }
    Err("未找到匹配规则".into())
}

/// op: nft.add_accept — append an accept rule to an existing user chain.
pub fn nft_add_accept(_state: &Shared, params: &Value) -> Result<Plan, String> {
    let family = p_str(params, "family")?;
    let table = p_str(params, "table")?;
    let chain = p_str(params, "chain")?;
    let proto = p_str(params, "proto")?;
    if !["tcp", "udp", "icmp", "any"].contains(&proto.as_str()) {
        return Err("proto 必须是 tcp/udp/icmp/any".into());
    }
    let port = params.get("port").and_then(|v| v.as_u64());
    if let Some(p) = port {
        if !valid_port(&p) {
            return Err("端口必须是 1-65535".into());
        }
    }
    let oif = params.get("oif").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !oif.is_empty() && !valid_ifname(&oif) {
        return Err(format!("非法接口名: {}", oif));
    }
    if !["inet", "ip", "ip6"].contains(&family.as_str())
        || !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        || !chain.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("非法的链标识".into());
    }

    let rd_id = util::short_id("acc");
    let mut desc_line = String::from("放行 ");
    if !oif.is_empty() {
        desc_line.push_str(&format!("→ {} ", oif));
    }
    desc_line.push_str(&proto);
    if let Some(p) = port {
        desc_line.push_str(&format!(":{}", p));
    }

    let mut plan = Plan::new("nft.add_accept", "添加转发放行规则", "medium");
    plan.description = format!("追加到 {} {} {}：{}", family, table, chain, desc_line);
    let comment = format!("rd:{} | {}", rd_id, desc_line);

    let mut argv = vec![
        "nft".into(),
        "add".into(),
        "rule".into(),
        family.clone(),
        table.clone(),
        chain.clone(),
    ];
    if !oif.is_empty() {
        argv.push("oifname".into());
        argv.push(format!("\"{}\"", oif));
    }
    if proto != "any" {
        argv.push(proto.clone());
        if let Some(p) = port {
            argv.push("dport".into());
            argv.push(p.to_string());
        }
    }
    argv.push("accept".into());
    argv.push("comment".into());
    argv.push(format!("\"{}\"", sanitize_comment(&comment)));

    plan.commands.push(CmdStep {
        argv,
        desc: format!("追加放行规则 {}", desc_line),
    });
    plan.rollback.push(RollbackStep::NftDeleteByComment {
        family,
        table,
        chain,
        comment,
        desc: "删除刚追加的放行规则".into(),
    });
    plan.warnings.push(
        "该规则追加到你现有的链中（不修改已有规则）。删除其它原有规则超出本面板能力，全部只读。".into(),
    );
    Ok(plan)
}

// ---------- PPPoE ----------

/// op: nm.create_pppoe — create a PPPoE dial-up connection.
pub fn nm_create_pppoe(state: &Shared, params: &Value) -> Result<Plan, String> {
    let name = p_str(params, "name")?;
    if !valid_hostname(&name) {
        return Err("连接名仅允许字母数字与 - _（如 WAN1-PPPoE）".into());
    }
    let ifname = p_str(params, "ifname")?;
    if !valid_ifname(&ifname) {
        return Err(format!("非法接口名: {}", ifname));
    }
    let username = p_str(params, "username")?;
    let password = params
        .get("password")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if username.len() > 128 || password.len() > 128 {
        return Err("账号/密码过长".into());
    }
    let service = params
        .get("service")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let mtu = params.get("mtu").and_then(|v| v.as_u64());
    if let Some(m) = mtu {
        if m < 576 || m > 9000 {
            return Err("MTU 必须在 576–9000".into());
        }
    }
    // duplicate name?
    let conns = nmd::connections(state.mode);
    if conns.iter().any(|c| c["name"].as_str() == Some(name.as_str())) {
        return Err(format!("同名连接已存在: {}", name));
    }

    let mut plan = Plan::new("nm.create_pppoe", "创建 PPPoE 拨号连接", "high");
    plan.description = format!("{} → {} (账号 {})", name, ifname, username);
    plan.risk = "high".into();

    let mut argv = util::argv(&[
        "nmcli", "connection", "add", "type", "pppoe",
        "con-name", &name, "ifname", &ifname,
        "pppoe.username", &username,
    ]);
    if !password.is_empty() {
        argv.push("pppoe.password".into());
        argv.push(password.clone());
    }
    if !service.is_empty() {
        argv.push("pppoe.service".into());
        argv.push(service.clone());
    }
    argv.push("connection.autoconnect".into());
    argv.push("yes".into());
    plan.commands.push(CmdStep {
        argv,
        desc: format!("创建 PPPoE 连接 {}", name),
    });
    if let Some(m) = mtu {
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &name, "ppp.mtu", &m.to_string()]),
            desc: format!("设置 ppp.mtu = {}", m),
        });
    }
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &name]),
        desc: format!("拨号 {}", name),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "delete", &name]),
        desc: format!("删除新建连接 {}", name),
    });
    plan.warnings.push(
        "拨号会立即占用该网卡；若该网卡承载管理连接，执行后管理会话可能中断。".into(),
    );
    plan.may_disconnect = true;
    Ok(plan)
}

/// op: nm.create_ethernet — create an ethernet connection (LAN port or DHCP/static WAN).
pub fn nm_create_ethernet(state: &Shared, params: &Value) -> Result<Plan, String> {
    let name = p_str(params, "name")?;
    if !valid_hostname(&name) {
        return Err("连接名仅允许字母数字与 - _（如 LAN1 / WAN2-DHCP）".into());
    }
    let ifname = p_str(params, "ifname")?;
    if !valid_ifname(&ifname) {
        return Err(format!("非法接口名: {}", ifname));
    }
    let method = params
        .get("method")
        .and_then(|v| v.as_str())
        .unwrap_or("auto")
        .to_string();
    if !["manual", "auto"].contains(&method.as_str()) {
        return Err("method 必须是 manual 或 auto".into());
    }
    let addresses = p_str_arr(params, "addresses");
    let gateway = params
        .get("gateway")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    let dns = p_str_arr(params, "dns");
    let metric = params.get("metric").and_then(|v| v.as_u64());
    if let Some(m) = metric {
        if m == 0 || m > 9999 {
            return Err("metric 必须在 1–9999".into());
        }
    }
    if method == "manual" {
        if addresses.is_empty() {
            return Err("静态模式至少需要一个地址（CIDR，如 192.168.1.1/24）".into());
        }
        for a in &addresses {
            if !valid_cidr(a) {
                return Err(format!("非法地址: {}（应为 如 192.168.1.1/24）", a));
            }
        }
        if !gateway.is_empty() && !valid_ipv4(&gateway) {
            return Err(format!("非法网关: {}", gateway));
        }
    }
    for d in &dns {
        if !valid_ipv4(d) && !d.contains(':') {
            return Err(format!("非法 DNS: {}", d));
        }
    }
    let conns = nmd::connections(state.mode);
    if conns.iter().any(|c| c["name"].as_str() == Some(name.as_str())) {
        return Err(format!("同名连接已存在: {}", name));
    }

    let role = if method == "auto" { "DHCP" } else { "静态" };
    let mut plan = Plan::new("nm.create_ethernet", "创建以太网连接", "high");
    plan.description = format!("{} → {} ({})", name, ifname, role);
    plan.risk = "high".into();

    let mut argv = util::argv(&[
        "nmcli", "connection", "add", "type", "ethernet",
        "con-name", &name, "ifname", &ifname,
        "ipv4.method", &method,
    ]);
    if method == "manual" {
        argv.push("ipv4.addresses".into());
        argv.push(addresses.join(","));
        if !gateway.is_empty() {
            argv.push("ipv4.gateway".into());
            argv.push(gateway.clone());
        }
    }
    if !dns.is_empty() {
        argv.push("ipv4.dns".into());
        argv.push(dns.join(","));
    }
    if let Some(m) = metric {
        argv.push("ipv4.route-metric".into());
        argv.push(m.to_string());
    }
    argv.push("connection.autoconnect".into());
    argv.push("yes".into());
    plan.commands.push(CmdStep {
        argv,
        desc: format!("创建以太网连接 {}", name),
    });
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &name]),
        desc: format!("激活 {}", name),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "delete", &name]),
        desc: format!("删除新建连接 {}", name),
    });
    plan.warnings.push(
        "新连接会立即占用该网卡；若该网卡承载管理连接或已有连接，执行后管理会话可能中断。".into(),
    );
    plan.may_disconnect = true;
    Ok(plan)
}

/// op: nm.set_ifname — rebind an existing connection to another NIC (WAN/LAN role swap).
pub fn nm_set_ifname(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    let ifname = p_str(params, "ifname")?;
    if !valid_ifname(&ifname) {
        return Err(format!("非法接口名: {}", ifname));
    }
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    let before = nm_keys(state.mode, &conn)?;
    let old = before
        .get("connection.interface-name")
        .cloned()
        .unwrap_or_default();
    if old == ifname {
        return Err(format!("连接 {} 已绑定 {}", conn, ifname));
    }

    let mut plan = Plan::new(
        "nm.set_ifname",
        &format!("换绑连接 {} 的网卡", conn),
        "high",
    );
    plan.description = format!(
        "{}: {} → {}",
        conn,
        if old.is_empty() { "(未绑定)".into() } else { old.clone() },
        ifname
    );
    plan.risk = "high".into();

    plan.commands.push(CmdStep {
        argv: util::argv(&[
            "nmcli", "connection", "modify", &conn,
            "connection.interface-name", &ifname,
        ]),
        desc: format!("绑定 {} → {}", conn, ifname),
    });
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重新激活 {}", conn),
    });
    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: vec![(
            "connection.interface-name".into(),
            old.clone(),
        )],
        desc: format!("还原 {} 的网卡绑定", conn),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重新激活 {}", conn),
    });
    plan.warnings.push(
        "换绑会把该连接迁移到另一块网卡（WAN/LAN 角色互换）。原网卡若无其它连接将失去配置，管理链路可能中断。".into(),
    );
    plan.may_disconnect = true;
    Ok(plan)
}

/// op: nm.update_pppoe — change username/password/service/mtu on existing PPPoE conn.
pub fn nm_update_pppoe(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    let before = nm_keys(state.mode, &conn)?;
    if before.get("connection.type").map(|t| t != "pppoe").unwrap_or(true)
        && state.mode == Mode::Live
    {
        // NM reports type as "pppoe" or "802-3-ethernet"; pppoe conn has pppoe.username
        if !before.contains_key("pppoe.username") {
            return Err(format!("连接 {} 不是 PPPoE 类型", conn));
        }
    }
    let username = params.get("username").and_then(|v| v.as_str()).map(|s| s.to_string());
    let password = params.get("password").and_then(|v| v.as_str()).map(|s| s.to_string());
    let service = params.get("service").and_then(|v| v.as_str()).map(|s| s.to_string());
    let mtu = params.get("mtu").and_then(|v| v.as_u64());
    if let Some(m) = mtu {
        if m < 576 || m > 9000 {
            return Err("MTU 必须在 576–9000".into());
        }
    }
    if username.is_none() && password.is_none() && service.is_none() && mtu.is_none() {
        return Err("没有要修改的字段".into());
    }

    let mut plan = Plan::new("nm.update_pppoe", "修改 PPPoE 拨号参数", "high");
    plan.description = format!("连接 {}", conn);
    plan.risk = "high".into();

    let mut restore: Vec<(String, String)> = vec![];
    if let Some(u) = &username {
        restore.push(("pppoe.username".into(), before.get("pppoe.username").cloned().unwrap_or_default()));
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "pppoe.username", u]),
            desc: "更新拨号账号".into(),
        });
    }
    if let Some(p) = &password {
        restore.push(("pppoe.password".into(), String::new())); // password not readable w/o --show-secrets
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "pppoe.password", p]),
            desc: "更新拨号密码".into(),
        });
        plan.warnings.push("密码由 nmcli 写入系统连接配置（root 权限可读）；回滚无法还原旧密码（不可读），仅还原其它字段。".into());
    }
    if let Some(sv) = &service {
        restore.push(("pppoe.service".into(), before.get("pppoe.service").cloned().unwrap_or_default()));
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "pppoe.service", sv]),
            desc: "更新 ISP 服务名".into(),
        });
    }
    if let Some(m) = mtu {
        restore.push(("ppp.mtu".into(), before.get("ppp.mtu").cloned().unwrap_or_default()));
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "ppp.mtu", &m.to_string()]),
            desc: format!("设置 ppp.mtu = {}", m),
        });
    }
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: "重拨生效".into(),
    });
    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: restore,
        desc: "还原拨号参数".into(),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: "按原参数重拨".into(),
    });
    warn_disconnect(&mut plan, state.mode, &conn);
    plan.may_disconnect = true;
    Ok(plan)
}

/// op: nm.reconnect — force redial (down + up).
pub fn nm_reconnect(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    let mut plan = Plan::new("nm.reconnect", "断线重拨", "high");
    plan.description = format!("重启连接 {}", conn);
    plan.risk = "high".into();
    plan.may_disconnect = true;
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "down", &conn]),
        desc: format!("断开 {}", conn),
    });
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重新连接 {}", conn),
    });
    // undo: bring it back up (if the up failed, rollback retries)
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("确保 {} 已连接", conn),
    });
    warn_disconnect(&mut plan, state.mode, &conn);
    Ok(plan)
}

// ---------- interface control ----------

/// op: nm.set_link — up/down an NM connection.
pub fn nm_set_link(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    let action = p_str(params, "action")?; // up | down
    if !["up", "down"].contains(&action.as_str()) {
        return Err("action 必须是 up 或 down".into());
    }
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    let mut plan = Plan::new(
        "nm.set_link",
        if action == "up" { "启用连接" } else { "停用连接" },
        "high",
    );
    plan.description = format!("nmcli connection {} {}", action, conn);
    plan.risk = "high".into();
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", &action, &conn]),
        desc: if action == "up" { format!("启用 {}", conn) } else { format!("停用 {}", conn) },
    });
    // undo: opposite action
    let undo = if action == "up" { "down" } else { "up" };
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", undo, &conn]),
        desc: format!("执行反向操作 connection {}", undo),
    });
    warn_disconnect(&mut plan, state.mode, &conn);
    plan.may_disconnect = true;
    Ok(plan)
}

/// op: nm.set_metric — dual-WAN exit priority (ipv4.route-metric + never-default).
pub fn nm_set_metric(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    let metric = params.get("metric").and_then(|v| v.as_u64());
    let never_default = params.get("never_default").and_then(|v| v.as_bool());
    if metric.is_none() && never_default.is_none() {
        return Err("没有要修改的字段".into());
    }
    if let Some(m) = metric {
        if m == 0 || m > 9999 {
            return Err("metric 必须是 1–9999（越小越优先）".into());
        }
    }
    let before = nm_keys(state.mode, &conn)?;
    let mut plan = Plan::new("nm.set_metric", "调整出口优先级", "high");
    plan.description = format!(
        "连接 {} · metric {} · never-default {}",
        conn,
        metric.map(|m| m.to_string()).unwrap_or_else(|| "不变".into()),
        never_default.map(|b| b.to_string()).unwrap_or_else(|| "不变".into()),
    );
    plan.risk = "high".into();

    let mut restore: Vec<(String, String)> = vec![];
    if let Some(m) = metric {
        restore.push(("ipv4.route-metric".into(), before.get("ipv4.route-metric").cloned().unwrap_or_default()));
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.route-metric", &m.to_string()]),
            desc: format!("设置 route-metric = {}", m),
        });
    }
    if let Some(nd) = never_default {
        restore.push(("ipv4.never-default".into(), before.get("ipv4.never-default").cloned().unwrap_or_default()));
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "ipv4.never-default", if nd { "yes" } else { "no" }]),
            desc: format!("设置 never-default = {}", nd),
        });
    }
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重激活 {}", conn),
    });
    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: restore,
        desc: "还原出口优先级属性".into(),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: "重激活连接".into(),
    });
    plan.warnings.push("双 WAN 场景下调整 metric 会切换默认出口；若这是你的管理链路，确认第二条 WAN 可达后再执行。".into());
    warn_disconnect(&mut plan, state.mode, &conn);
    Ok(plan)
}

/// op: nm.set_mtu — MTU + optional MAC clone for an ethernet connection.
pub fn nm_set_mtu(state: &Shared, params: &Value) -> Result<Plan, String> {
    let conn = p_str(params, "connection")?;
    if !nm_conn_exists(state.mode, &conn) {
        return Err(format!("连接不存在: {}", conn));
    }
    let mtu = params.get("mtu").and_then(|v| v.as_u64());
    let mac = params
        .get("mac")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if mtu.is_none() && mac.is_empty() {
        return Err("没有要修改的字段".into());
    }
    if let Some(m) = mtu {
        if m < 68 || m > 9000 {
            return Err("MTU 必须在 68–9000".into());
        }
    }
    if !mac.is_empty() && !valid_mac(&mac) {
        return Err(format!("非法 MAC: {}", mac));
    }
    let before = nm_keys(state.mode, &conn)?;
    let mut plan = Plan::new("nm.set_mtu", "修改 MTU / MAC", "medium");
    plan.description = format!(
        "连接 {} · MTU {} · MAC {}",
        conn,
        mtu.map(|m| m.to_string()).unwrap_or_else(|| "不变".into()),
        if mac.is_empty() { "不变" } else { &mac },
    );
    let mut restore: Vec<(String, String)> = vec![];
    if let Some(m) = mtu {
        for key in ["802-3.ethernet.mtu", "ppp.mtu", "802-11.mtu"] {
            if before.contains_key(key) {
                restore.push((key.to_string(), before.get(key).cloned().unwrap_or_default()));
                plan.commands.push(CmdStep {
                    argv: util::argv(&["nmcli", "connection", "modify", &conn, key, &m.to_string()]),
                    desc: format!("设置 {} = {}", key, m),
                });
            }
        }
        if restore.is_empty() {
            // generic fallback (NM accepts per-type keys only; use 802-3)
            restore.push(("802-3.ethernet.mtu".into(), before.get("802-3.ethernet.mtu").cloned().unwrap_or_default()));
            plan.commands.push(CmdStep {
                argv: util::argv(&["nmcli", "connection", "modify", &conn, "802-3.ethernet.mtu", &m.to_string()]),
                desc: format!("设置 802-3.ethernet.mtu = {}", m),
            });
        }
    }
    if !mac.is_empty() {
        restore.push((
            "802-3.ethernet.cloned-mac-address".into(),
            before.get("802-3.ethernet.cloned-mac-address").cloned().unwrap_or_default(),
        ));
        plan.commands.push(CmdStep {
            argv: util::argv(&["nmcli", "connection", "modify", &conn, "802-3.ethernet.cloned-mac-address", &mac]),
            desc: format!("设置克隆 MAC = {}", mac),
        });
    }
    plan.commands.push(CmdStep {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: format!("重激活 {}", conn),
    });
    plan.rollback.push(RollbackStep::NmRestoreKeys {
        connection: conn.clone(),
        keys: restore,
        desc: "还原 MTU/MAC".into(),
    });
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["nmcli", "connection", "up", &conn]),
        desc: "重激活连接".into(),
    });
    warn_disconnect(&mut plan, state.mode, &conn);
    Ok(plan)
}

/// op: nft.set_masquerade — toggle masquerade for one exit iface in OUR table.
pub fn nft_set_masquerade(state: &Shared, params: &Value) -> Result<Plan, String> {
    let oif = p_str(params, "oif")?;
    if !valid_ifname(&oif) {
        return Err(format!("非法接口名: {}", oif));
    }
    let enable = params
        .get("enable")
        .and_then(|v| v.as_bool())
        .ok_or("缺少参数 enable")?;

    let nat = natd::bundle(state.mode);
    let table_exists = nat["nft"]["managed"]["table_exists"].as_bool().unwrap_or(false);

    // find existing rd masquerade rule for this iface
    let comment = format!("rd:masq-{} | masquerade {}", oif, oif);
    let existing = nat["nft"]["managed"]["rules"]
        .as_array()
        .map(|rs| {
            rs.iter().any(|r| {
                let c = r["comment"].as_str().unwrap_or("");
                c.starts_with(&format!("rd:masq-{} ", oif)) // trailing space: exact iface, not eth10
                    || c == format!("rd:masq-{}", oif)
            })
        })
        .unwrap_or(false);

    if enable && existing {
        return Err(format!("接口 {} 的托管 masquerade 已存在", oif));
    }
    if !enable && !existing {
        return Err(format!("未找到接口 {} 的托管 masquerade 规则", oif));
    }

    let mut plan = Plan::new(
        "nft.set_masquerade",
        if enable { "开启 MASQUERADE" } else { "关闭 MASQUERADE" },
        "high",
    );
    plan.description = format!("出口 {} · {}", oif, if enable { "启用 MASQUERADE" } else { "禁用 MASQUERADE" });
    plan.risk = "high".into();

    if !table_exists {
        plan.commands.push(CmdStep {
            argv: util::argv(&["nft", "add", "table", "inet", "routedeck"]),
            desc: "创建托管表 inet routedeck".into(),
        });
    }
    // ensure postrouting nat chain
    let chain_exists = nat["nft"]["tables"]
        .as_array()
        .map(|ts| {
            ts.iter().any(|t| t["name"] == "routedeck"
                && t["chains"].as_array().map(|cs| cs.iter().any(|c| c["name"] == "postrouting")).unwrap_or(false))
        })
        .unwrap_or(false);
    if !chain_exists {
        plan.commands.push(CmdStep {
            argv: vec![
                "nft".into(), "add".into(), "chain".into(), "inet".into(), "routedeck".into(),
                "postrouting".into(),
                "{ type nat hook postrouting priority srcnat; policy accept; }".into(),
            ],
            desc: "创建托管链 postrouting (nat)".into(),
        });
    }

    if enable {
        plan.commands.push(CmdStep {
            argv: vec![
                "nft".into(), "add".into(), "rule".into(), "inet".into(), "routedeck".into(),
                "postrouting".into(), "oifname".into(), format!("\"{}\"", oif),
                "masquerade".into(), "comment".into(), format!("\"{}\"", sanitize_comment(&comment)),
            ],
            desc: format!("对 {} 启用 masquerade", oif),
        });
        plan.rollback.push(RollbackStep::NftDeleteByComment {
            family: "inet".into(),
            table: "routedeck".into(),
            chain: "postrouting".into(),
            comment,
            desc: "撤销 masquerade".into(),
        });
        plan.warnings.push(
            "只影响 RouteDeck 托管规则；你现有的 masquerade 不受影响。关闭该出口的 NAT 会使该 WAN 下的内网主机无法出网。".into(),
        );
    } else {
        let rule = find_rd_rule(state.mode, "inet", "routedeck", "postrouting", &format!("rd:masq-{}", oif))?;
        let handle = rule["handle"].as_u64().unwrap_or(0);
        plan.commands.push(CmdStep {
            argv: vec![
                "nft".into(), "delete".into(), "rule".into(), "inet".into(), "routedeck".into(),
                "postrouting".into(), "handle".into(), handle.to_string(),
            ],
            desc: format!("对 {} 关闭 masquerade", oif),
        });
        // undo: re-add
        plan.rollback.push(RollbackStep::Cmd {
            argv: vec![
                "nft".into(), "add".into(), "rule".into(), "inet".into(), "routedeck".into(),
                "postrouting".into(), "oifname".into(), format!("\"{}\"", oif),
                "masquerade".into(), "comment".into(), format!("\"{}\"", sanitize_comment(&comment)),
            ],
            desc: "恢复 masquerade".into(),
        });
        plan.warnings.push("关闭后该出口的内网流量将不再做源地址转换（除非你现有规则中另有 masquerade）。".into());
    }
    Ok(plan)
}

/// op: nft.add_dmz — full-port DNAT to one internal host.
pub fn nft_add_dmz(state: &Shared, params: &Value) -> Result<Plan, String> {
    let wan_if = params.get("wan_if").and_then(|v| v.as_str()).unwrap_or("").trim().to_string();
    if !wan_if.is_empty() && !valid_ifname(&wan_if) {
        return Err(format!("非法接口名: {}", wan_if));
    }
    let to_addr = p_str(params, "to_addr")?;
    if !valid_ipv4(&to_addr) {
        return Err(format!("非法内网地址: {}", to_addr));
    }
    let note = params.get("note").and_then(|v| v.as_str()).unwrap_or("").to_string();

    let rd_id = util::short_id("dmz");
    let where_ = if wan_if.is_empty() { "任意入接口".to_string() } else { wan_if.clone() };
    let desc_line = sanitize_comment(&format!("DMZ → {} ({}){}", to_addr, where_,
        if note.is_empty() { String::new() } else { format!(" · {}", note) }));

    let mut plan = Plan::new("nft.add_dmz", "添加 DMZ（全端口转发）", "high");
    plan.description = format!("所有端口 → {} · 入口 {}", to_addr, where_);
    plan.risk = "high".into();
    nft_ensure_table_chain(&mut plan, state.mode);

    let comment = format!("rd:{} | {}", rd_id, desc_line);
    let mut argv = vec![
        "nft".into(), "add".into(), "rule".into(), "inet".into(), "routedeck".into(), "prerouting".into(),
    ];
    if !wan_if.is_empty() {
        argv.push("iifname".into());
        argv.push(format!("\"{}\"", wan_if));
    }
    argv.push("dnat".into());
    argv.push("to".into());
    argv.push(to_addr.clone());
    argv.push("comment".into());
    argv.push(format!("\"{}\"", sanitize_comment(&comment)));
    plan.commands.push(CmdStep {
        argv,
        desc: format!("添加 DMZ → {}", to_addr),
    });
    plan.rollback.push(RollbackStep::NftDeleteByComment {
        family: "inet".into(),
        table: "routedeck".into(),
        chain: "prerouting".into(),
        comment,
        desc: format!("删除 DMZ → {}", to_addr),
    });
    plan.warnings.push(
        "⚠ DMZ 意味着目标主机所有入站端口都暴露到该 WAN；仅在内网主机有独立防火墙时使用。仍需 forward 链放行（如未放行可同时添加 accept 规则）。".into(),
    );
    Ok(plan)
}

// ---------- dnsmasq snippet management ----------

/// Snippet layout: header → upstreams → scope+options → bindings → hosts.
fn render_snippet(
    upstreams: &[String],
    bindings: &[Value],
    scope: &Value,
    opts: &Value,
    hosts: &[Value],
) -> String {
    let mut s = String::from(dhcpdns::OUR_HEADER);
    s.push('\n');
    for u in upstreams {
        s.push_str(&format!("server={}\n", u));
    }
    if !upstreams.is_empty() {
        s.push('\n');
    }
    if scope.is_object() {
        let start = scope["start"].as_str().unwrap_or("");
        let end = scope["end"].as_str().unwrap_or("");
        let netmask = scope["netmask"].as_str().unwrap_or("");
        let lease = scope["lease"].as_str().unwrap_or("");
        if !start.is_empty() && !end.is_empty() {
            let lease = if lease.is_empty() { "12h" } else { lease };
            if netmask.is_empty() {
                s.push_str(&format!("dhcp-range={},{},{}\n", start, end, lease));
            } else {
                s.push_str(&format!("dhcp-range={},{},{},{}\n", start, end, netmask, lease));
            }
            let gw = opts["gateway"].as_str().unwrap_or("");
            if !gw.is_empty() {
                s.push_str(&format!("dhcp-option=3,{}\n", gw));
            }
            let dns_list: Vec<&str> = opts["dns"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str()).collect())
                .unwrap_or_default();
            if !dns_list.is_empty() {
                s.push_str(&format!("dhcp-option=6,{}\n", dns_list.join(",")));
            }
            let domain = opts["domain"].as_str().unwrap_or("");
            if !domain.is_empty() {
                s.push_str(&format!("dhcp-option=15,{}\n", domain));
            }
            s.push('\n');
        }
    }
    for b in bindings {
        let mac = b["mac"].as_str().unwrap_or("");
        let ip = b["ip"].as_str().unwrap_or("");
        let name = b["name"].as_str().unwrap_or("");
        if mac.is_empty() || ip.is_empty() {
            continue;
        }
        if name.is_empty() {
            s.push_str(&format!("dhcp-host={},{}\n", mac, ip));
        } else {
            s.push_str(&format!("dhcp-host={},{},{}\n", mac, ip, name));
        }
    }
    if !bindings.is_empty() && !hosts.is_empty() {
        s.push('\n');
    }
    for h in hosts {
        let name = h["name"].as_str().unwrap_or("");
        let ip = h["ip"].as_str().unwrap_or("");
        if name.is_empty() || ip.is_empty() {
            continue;
        }
        s.push_str(&format!("address=/{}/{}\n", name, ip));
    }
    s
}

struct SnippetState {
    exists: bool,
    ours: bool,
    upstreams: Vec<String>,
    bindings: Vec<Value>,
    scope: Value,
    opts: Value,
    hosts: Vec<Value>,
    content: String,
}

fn load_snippet(mode: Mode) -> SnippetState {
    if mode == Mode::Mock {
        let our = crate::discovery::mock::dhcp()["dnsmasq"]["our_snippet"].clone();
        let arr = |k: &str| -> Vec<Value> { our[k].as_array().cloned().unwrap_or_default() };
        return SnippetState {
            exists: our["exists"].as_bool().unwrap_or(false),
            ours: our["ours"].as_bool().unwrap_or(false),
            upstreams: our["upstreams"]
                .as_array()
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            bindings: arr("bindings"),
            scope: our["scope"].clone(),
            opts: our["options"].clone(),
            hosts: arr("hosts"),
            content: our["content"].as_str().unwrap_or("").to_string(),
        };
    }
    let exists = std::path::Path::new(dhcpdns::OUR_SNIPPET).exists();
    let content = util::read_file(dhcpdns::OUR_SNIPPET);
    let ours = content.contains("Managed by RouteDeck");
    let parsed = dhcpdns::parse_our_snippet();
    let arr = |k: &str| -> Vec<Value> { parsed[k].as_array().cloned().unwrap_or_default() };
    SnippetState {
        exists,
        ours,
        upstreams: parsed["upstreams"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default(),
        bindings: arr("bindings"),
        scope: parsed["scope"].clone(),
        opts: parsed["options"].clone(),
        hosts: arr("hosts"),
        content,
    }
}

/// Common prep: conf-dir inclusion check (read-only detection).
/// Returns (plan, need_conf_dir_line).
fn dnsmasq_prep(state: &Shared, op: &str, title: &str) -> Result<(Plan, bool), String> {
    let mut plan = Plan::new(op, title, "medium");
    let included = dhcpdns::bundle(state.mode)["dnsmasq"]["conf_dir_included"].clone();
    let need_append = included.is_null();
    if need_append && state.mode == Mode::Live {
        plan.warnings.push(
            "/etc/dnsmasq.conf 未包含 /etc/dnsmasq.d 目录，将追加一行 conf-dir（原文件会先备份）。".into(),
        );
    }
    plan.warnings.push("修改后将执行 systemctl reload dnsmasq 生效。".into());
    Ok((plan, need_append))
}

fn push_snippet_files(
    state: &Shared,
    plan: &mut Plan,
    st: &SnippetState,
    new_content: String,
    need_append: bool,
) -> Result<(), String> {
    if st.exists && !st.ours && state.mode == Mode::Live {
        return Err(format!(
            "{} 已存在且不是 RouteDeck 生成的文件（无标记），拒绝覆盖。请先人工确认其内容。",
            dhcpdns::OUR_SNIPPET
        ));
    }
    // conf-dir append (only when truly missing)
    if need_append && state.mode == Mode::Live {
        let conf = util::read_file("/etc/dnsmasq.conf");
        if !conf.contains("conf-dir=") || conf.lines().all(|l| l.trim_start().starts_with('#')) {
            let backup = state.backup_write("/etc/dnsmasq.conf", conf.as_bytes(), "conf-dir-append");
            let expect = sha256_str(&conf);
            let mut new_conf = conf.clone();
            if !new_conf.ends_with('\n') {
                new_conf.push('\n');
            }
            new_conf.push_str("conf-dir=/etc/dnsmasq.d/,*.conf\n");
            plan.files.push(FileStep {
                path: "/etc/dnsmasq.conf".into(),
                content: new_conf,
                expect_sha: Some(expect),
                backup_id: Some(backup.clone()),
                created: false,
                desc: "向 /etc/dnsmasq.conf 追加 conf-dir 指令".into(),
            });
            plan.rollback.push(RollbackStep::FileRestore {
                path: "/etc/dnsmasq.conf".into(),
                backup_id: Some(backup),
                desc: "还原 /etc/dnsmasq.conf".into(),
            });
        }
    }
    // our snippet file
    let (old_content, created, backup_id) = if st.exists {
        (
            st.content.clone(),
            false,
            Some(state.backup_write(dhcpdns::OUR_SNIPPET, st.content.as_bytes(), "snippet")),
        )
    } else {
        (String::new(), true, None)
    };
    let expect = if st.exists { Some(sha256_str(&old_content)) } else { None };
    plan.files.push(FileStep {
        path: dhcpdns::OUR_SNIPPET.into(),
        content: new_content,
        expect_sha: expect,
        backup_id: backup_id.clone(),
        created,
        desc: "写入 RouteDeck 托管片段".into(),
    });
    plan.rollback.insert(
        0,
        RollbackStep::FileRestore {
            path: dhcpdns::OUR_SNIPPET.into(),
            backup_id,
            desc: if created { "删除新建的片段文件" } else { "还原片段文件" }.into(),
        },
    );
    // reload LAST in undo order (undo order: file restore first, then reload —
    // we push reload at the END of rollback so it runs after restore? No:
    // rollback executes in listed order, so append reload at end.)
    plan.rollback.push(RollbackStep::Cmd {
        argv: util::argv(&["systemctl", "reload", "dnsmasq"]),
        desc: "重新加载 dnsmasq".into(),
    });
    Ok(())
}

/// op: dnsmasq.add_binding — DHCP static lease.
pub fn dnsmasq_add_binding(state: &Shared, params: &Value) -> Result<Plan, String> {
    let mac = p_str(params, "mac")?.to_lowercase();
    let ip = p_str(params, "ip")?;
    let name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !valid_mac(&mac) {
        return Err(format!("非法 MAC: {}", mac));
    }
    if !valid_ipv4(&ip) {
        return Err(format!("非法 IP: {}", ip));
    }
    if !name.is_empty() && !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(format!("主机名仅允许字母数字与 - _: {}", name));
    }

    let st = load_snippet(state.mode);
    if st.bindings.iter().any(|b| b["mac"].as_str().unwrap_or("") == mac) {
        return Err(format!("该 MAC 已存在静态绑定: {}", mac));
    }
    if st.bindings.iter().any(|b| b["ip"].as_str().unwrap_or("") == ip) {
        return Err(format!("该 IP 已存在静态绑定: {}", ip));
    }

    let (mut plan, need_append) = dnsmasq_prep(state, "dnsmasq.add_binding", "添加 DHCP 静态绑定")?;
    plan.description = format!("{} → {}{}", ip, mac, if name.is_empty() { String::new() } else { format!(" ({})", name) });

    let mut bindings = st.bindings.clone();
    bindings.push(json!({"mac": mac, "ip": ip, "name": name}));
    let new_content = render_snippet(&st.upstreams, &bindings, &st.scope, &st.opts, &st.hosts);
    push_snippet_files(state, &mut plan, &st, new_content, need_append)?;
    Ok(plan)
}

/// op: dnsmasq.del_binding — remove by mac.
pub fn dnsmasq_del_binding(state: &Shared, params: &Value) -> Result<Plan, String> {
    let mac = p_str(params, "mac")?.to_lowercase();
    let st = load_snippet(state.mode);
    if !st.bindings.iter().any(|b| b["mac"].as_str().unwrap_or("") == mac) {
        return Err(format!("未找到该 MAC 的绑定: {}", mac));
    }
    let (mut plan, need_append) = dnsmasq_prep(state, "dnsmasq.del_binding", "删除 DHCP 静态绑定")?;
    plan.description = format!("移除 {}", mac);
    let bindings: Vec<Value> = st
        .bindings
        .iter()
        .filter(|b| b["mac"].as_str().unwrap_or("") != mac)
        .cloned()
        .collect();
    let new_content = render_snippet(&st.upstreams, &bindings, &st.scope, &st.opts, &st.hosts);
    push_snippet_files(state, &mut plan, &st, new_content, need_append)?;
    Ok(plan)
}

/// op: dnsmasq.set_upstreams — replace upstream DNS servers in our snippet.
pub fn dnsmasq_set_upstreams(state: &Shared, params: &Value) -> Result<Plan, String> {
    let servers = p_str_arr(params, "servers");
    if servers.is_empty() {
        return Err("至少需要一个上游 DNS".into());
    }
    for s in &servers {
        if !valid_ipv4(s) && !s.contains(':') {
            return Err(format!("非法 DNS 地址: {}", s));
        }
    }
    let st = load_snippet(state.mode);
    let (mut plan, need_append) = dnsmasq_prep(state, "dnsmasq.set_upstreams", "设置上游 DNS")?;
    plan.description = format!("server= {}", servers.join(", "));
    plan.warnings.push(
        "上游将写入 RouteDeck 片段；若其它配置文件中也存在 server=，两者会合并生效（dnsmasq 语义）。".into(),
    );
    let new_content = render_snippet(&servers, &st.bindings, &st.scope, &st.opts, &st.hosts);
    push_snippet_files(state, &mut plan, &st, new_content, need_append)?;
    Ok(plan)
}

/// Shared conflict check for DHCP-affecting writes. Hard-stops on NM ICS.
fn dhcp_conflict_check(state: &Shared, plan: &mut Plan) -> Result<(), String> {
    let bundle = dhcpdns::bundle(state.mode);
    // NM ICS managing DHCP on the same LAN → refuse (two DHCP servers = disaster).
    if let Some(ics) = bundle["nm_ics"].as_array() {
        if !ics.is_empty() {
            let names: Vec<&str> = ics
                .iter()
                .filter_map(|i| i["name"].as_str())
                .collect();
            return Err(format!(
                "检测到 NetworkManager 共享网络 (ICS) 正在提供 DHCP：{}。同一网段两个 DHCP 服务会互相冲突，已拒绝执行。请先在 NM 中停用共享，或改用 NM 管理 DHCP。",
                names.join(", ")
            ));
        }
    }
    // Existing dhcp-range elsewhere → strong warning (may be another subnet, may overlap).
    if let Some(fr) = bundle["foreign_ranges"].as_array() {
        if !fr.is_empty() {
            let lines: Vec<String> = fr
                .iter()
                .map(|r| format!("{} :: {}", r["file"].as_str().unwrap_or("?"), r["line"].as_str().unwrap_or("?")))
                .collect();
            plan.warnings.push(format!(
                "⚠ 其它配置文件已声明 dhcp-range（共 {} 处），与新作用域可能重叠：\n{}\n如网段重叠，客户端会随机收到错误地址。请确认后再执行。",
                fr.len(),
                lines.join("\n")
            ));
            plan.may_disconnect = false;
        }
    }
    // Kea / ISC dhcpd present → warn.
    if bundle["kea"]["present"] == true || bundle["isc"]["present"] == true {
        plan.warnings.push("检测到 Kea/ISC dhcpd 配置文件存在；若其服务也在运行，会与 dnsmasq 冲突。".into());
    }
    Ok(())
}

/// op: dnsmasq.set_scope — DHCP range + options (gateway/dns/domain).
pub fn dnsmasq_set_scope(state: &Shared, params: &Value) -> Result<Plan, String> {
    let start = p_str(params, "start")?;
    let end = p_str(params, "end")?;
    if !valid_ipv4(&start) || !valid_ipv4(&end) {
        return Err("起止地址必须是合法 IPv4（如 192.168.1.100）".into());
    }
    let ip2u = |s: &str| -> u32 {
        s.split('.')
            .filter_map(|p| p.parse::<u32>().ok())
            .fold(0, |acc, x| (acc << 8) | x)
    };
    if ip2u(&start) > ip2u(&end) {
        return Err("起始地址不能大于结束地址".into());
    }
    let netmask = params
        .get("netmask")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !netmask.is_empty() && !valid_ipv4(&netmask) {
        return Err(format!("非法子网掩码: {}", netmask));
    }
    let lease = params
        .get("lease")
        .and_then(|v| v.as_str())
        .unwrap_or("12h")
        .trim()
        .to_string();
    // lease: digits + s/m/h/d, or "infinite"
    let lease_ok = lease == "infinite"
        || (!lease.is_empty()
            && lease.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
            && lease.chars().all(|c| c.is_ascii_digit() || "smhd".contains(c)));
    if !lease_ok {
        return Err("租期格式应如 12h / 30m / 1d / infinite".into());
    }
    let gateway = params
        .get("gateway")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !gateway.is_empty() && !valid_ipv4(&gateway) {
        return Err(format!("非法网关: {}", gateway));
    }
    let dns = p_str_arr(params, "dns");
    for d in &dns {
        if !valid_ipv4(d) && !d.contains(':') {
            return Err(format!("非法 DNS: {}", d));
        }
    }
    let domain = params
        .get("domain")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_string();
    if !domain.is_empty()
        && !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
    {
        return Err("域名仅允许字母数字与 - . _".into());
    }

    let st = load_snippet(state.mode);
    let (mut plan, need_append) = dnsmasq_prep(state, "dnsmasq.set_scope", "设置 DHCP 作用域与选项")?;
    dhcp_conflict_check(state, &mut plan)?;
    let dns_joined = dns.join(",");
    plan.description = format!(
        "范围 {} – {}{} · 租期 {} · 网关 {} · DNS {}{}",
        start,
        end,
        if netmask.is_empty() { String::new() } else { format!(" ({})", netmask) },
        lease,
        if gateway.is_empty() { "-" } else { &gateway },
        if dns.is_empty() { "-" } else { &dns_joined },
        if domain.is_empty() { String::new() } else { format!(" · 域 {}", domain) },
    );
    plan.risk = "high".into();

    let scope = json!({"start": start, "end": end, "netmask": netmask, "lease": lease});
    let opts = json!({"gateway": gateway, "dns": dns, "domain": domain});
    let new_content = render_snippet(&st.upstreams, &st.bindings, &scope, &opts, &st.hosts);
    push_snippet_files(state, &mut plan, &st, new_content, need_append)?;
    Ok(plan)
}

/// op: dnsmasq.set_hosts — replace local DNS records (address=/name/ip).
pub fn dnsmasq_set_hosts(state: &Shared, params: &Value) -> Result<Plan, String> {
    let hosts = params
        .get("hosts")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    for h in &hosts {
        let name = h["name"].as_str().unwrap_or("");
        let ip = h["ip"].as_str().unwrap_or("");
        if name.is_empty() || !valid_ipv4(ip) {
            return Err(format!("非法记录: name={} ip={}", name, ip));
        }
        if name.contains('/') || name.contains(' ') || name.contains(',') {
            return Err(format!("非法域名: {}", name));
        }
    }
    let st = load_snippet(state.mode);
    let (mut plan, need_append) = dnsmasq_prep(state, "dnsmasq.set_hosts", "更新本地域名解析")?;
    plan.description = format!("address= {} 条记录", hosts.len());
    let new_content = render_snippet(&st.upstreams, &st.bindings, &st.scope, &st.opts, &hosts);
    push_snippet_files(state, &mut plan, &st, new_content, need_append)?;
    Ok(plan)
}

/// op: file.restore — restore a backup (via plan for confirmation).
pub fn file_restore(state: &Shared, params: &Value) -> Result<Plan, String> {
    let backup_id = p_str(params, "backup_id")?;
    if backup_id.contains('/') || backup_id.contains("..") || backup_id.contains('\\') {
        return Err("非法备份 id".into());
    }
    let bytes = state
        .backup_read(&backup_id)
        .ok_or_else(|| format!("备份不存在: {}", backup_id))?;
    // find original path from index
    let idx = state.backup_list();
    let entry = idx
        .iter()
        .find(|e| e["id"].as_str() == Some(backup_id.as_str()))
        .cloned()
        .ok_or_else(|| "备份索引中未找到该条目".to_string())?;
    let path = entry["path"].as_str().unwrap_or("").to_string();
    if path.is_empty() || path.contains("..") {
        return Err("备份条目缺少合法路径".into());
    }

    let mut plan = Plan::new("file.restore", "还原文件备份", "high");
    plan.description = format!("将 {} 还原到 {} 的备份内容（{} 字节）", path, entry["ts"].as_str().unwrap_or("?"), bytes.len());

    let current = std::fs::read(&path).ok();
    let created = current.is_none();
    let cur_backup = current
        .as_ref()
        .map(|b| state.backup_write(&path, b, "pre-restore"))
        .unwrap_or_default();
    let expect = current.as_ref().map(|b| sha256_hex(b));
    let content = String::from_utf8_lossy(&bytes).into_owned();
    plan.files.push(FileStep {
        path: path.clone(),
        content,
        expect_sha: expect,
        backup_id: if cur_backup.is_empty() { None } else { Some(cur_backup.clone()) },
        created,
        desc: format!("还原 {}", path),
    });
    plan.rollback.push(RollbackStep::FileRestore {
        path,
        backup_id: if cur_backup.is_empty() { None } else { Some(cur_backup) },
        desc: "撤销本次还原".into(),
    });
    Ok(plan)
}

// ---------- external helpers used by rollback ----------

pub fn nft_delete_by_comment(family: &str, table: &str, chain: &str, comment: &str) -> Result<String, String> {
    let rule = find_rd_rule(Mode::Live, family, table, chain, comment)?;
    let handle = rule["handle"].as_u64().unwrap_or(0);
    let out = util::exec(&util::argv(&[
        "nft", "delete", "rule", family, table, chain, "handle", &handle.to_string(),
    ]))
    .map_err(|e| e.to_string())?;
    if !out.ok() {
        return Err(format!("nft delete 失败: {}", out.stderr.trim()));
    }
    Ok(format!("删除规则 handle {} ({} {} {})", handle, family, table, chain))
}

pub fn nm_restore_keys(connection: &str, keys: &[(String, String)]) -> Result<(), String> {
    for (k, v) in keys {
        let out = util::exec(&util::argv(&["nmcli", "connection", "modify", connection, k, v]))
            .map_err(|e| e.to_string())?;
        if !out.ok() {
            return Err(format!("还原 {}={} 失败: {}", k, v, out.stderr.trim()));
        }
    }
    Ok(())
}

// ---------- dispatcher ----------

pub fn build_plan(state: &Shared, op: &str, params: &Value) -> Result<Plan, String> {
    match op {
        "nm.apply_ip" => nm_apply_ip(state, params),
        "nm.add_route" => nm_add_route(state, params),
        "nm.del_route" => nm_del_route(state, params),
        "nm.create_pppoe" => nm_create_pppoe(state, params),
        "nm.create_ethernet" => nm_create_ethernet(state, params),
        "nm.set_ifname" => nm_set_ifname(state, params),
        "nm.update_pppoe" => nm_update_pppoe(state, params),
        "nm.reconnect" => nm_reconnect(state, params),
        "nm.set_link" => nm_set_link(state, params),
        "nm.set_metric" => nm_set_metric(state, params),
        "nm.set_mtu" => nm_set_mtu(state, params),
        "nft.add_forward" => nft_add_forward(state, params),
        "nft.del_rule" => nft_del_rule(state, params),
        "nft.add_accept" => nft_add_accept(state, params),
        "nft.set_masquerade" => nft_set_masquerade(state, params),
        "nft.add_dmz" => nft_add_dmz(state, params),
        "dnsmasq.add_binding" => dnsmasq_add_binding(state, params),
        "dnsmasq.del_binding" => dnsmasq_del_binding(state, params),
        "dnsmasq.set_upstreams" => dnsmasq_set_upstreams(state, params),
        "dnsmasq.set_scope" => dnsmasq_set_scope(state, params),
        "dnsmasq.set_hosts" => dnsmasq_set_hosts(state, params),
        "file.restore" => file_restore(state, params),
        _ => Err(format!("未知操作: {}", op)),
    }
}
