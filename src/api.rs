use crate::backend::{self, ops, ApplyResult};
use crate::discovery;
use crate::state::{authorized, AppState, Mode, Shared};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use include_dir::{include_dir, Dir};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

pub static WEB: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/web/static");

/// Error helper.
fn err(status: StatusCode, msg: &str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": msg })))
}

/// Wrap blocking discovery work in spawn_blocking.
async fn blocking<F, T>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f).await.unwrap()
}

// ---------- middleware-ish guard ----------

fn check(state: &Shared, headers: &HeaderMap, q: &Option<String>) -> Result<(), Response> {
    if authorized(state, headers, q.as_deref()) {
        Ok(())
    } else {
        Err(err(StatusCode::UNAUTHORIZED, "未授权：需要访问令牌").1.into_response())
    }
}

// ---------- handlers ----------

async fn h_status(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::status(mode)).await;
    Json(json!({
        "version": v["version"],
        "mode": v["mode"],
        "hostname": v["hostname"],
        "os": v["os"],
        "kernel": v["kernel"],
        "uptime_secs": v["uptime_secs"],
        "token_required": state.token.is_some(),
        "data_dir": state.data_dir.to_string_lossy(),
    }))
    .into_response()
}

async fn h_detection(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let saved = state.load_detection();
    let fresh = blocking(move || discovery::detection(mode)).await;
    Json(json!({"fresh": fresh, "saved": saved})).into_response()
}

async fn h_overview(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let (host, ifaces, routes, nat, dhcp, svc, docker) = blocking(move || {
        (
            discovery::host::host_info(mode),
            discovery::net::interfaces(mode),
            discovery::net::routes(mode),
            discovery::nat::bundle(mode),
            discovery::dhcpdns::bundle(mode),
            discovery::services::bundle(mode),
            discovery::docker::bundle(mode),
        )
    })
    .await;

    // rates + cpu from shared delta sample
    let (rx, tx) = discovery::host::rx_tx_bytes(mode);
    let cpu_total_idle = if mode == Mode::Mock {
        (0, 0)
    } else {
        // read /proc/stat via helper (returns (total, idle))
        crate::discovery::host::proc_stat_cpu_pub()
    };
    let sample = state.net_sample(rx, tx, cpu_total_idle.0, cpu_total_idle.1);
    let (rx_bps, tx_bps, cpu_pct) = match sample {
        Some((r, t, c)) => (r, t, Some(c)),
        None => (0, 0, discovery::host::cpu_pct(mode, None)),
    };

    let if_list = ifaces["interfaces"].as_array().cloned().unwrap_or_default();
    let mut if_light = vec![];
    for i in &if_list {
        if i["category"] == "loopback" {
            continue;
        }
        if_light.push(json!({
            "name": i["name"],
            "category": i["category"],
            "up": i["up"],
            "addr4": i["addr4"],
            "is_default": i["is_default"],
        }));
    }

    // WebUI 入口候选：LAN 侧地址优先（up、非回环、非默认出口）
    let mut lan_ips: Vec<String> = vec![];
    let mut wan_ips: Vec<String> = vec![];
    for i in &if_list {
        if i["category"] == "loopback" || i["up"] != json!(true) {
            continue;
        }
        let is_default = i["is_default"] == json!(true);
        for a in i["addr4"].as_array().map(|v| v.iter()).into_iter().flatten() {
            let Some(s) = a.as_str() else { continue };
            let ip = s.split('/').next().unwrap_or("");
            if ip.is_empty() || ip.starts_with("127.") {
                continue;
            }
            if is_default {
                wan_ips.push(ip.to_string());
            } else {
                lan_ips.push(ip.to_string());
            }
        }
    }

    Json(json!({
        "host": host,
        "net": {"rx_bps": rx_bps, "tx_bps": tx_bps, "cpu_pct": cpu_pct},
        "interfaces": if_light,
        "counts": {
            "interfaces": if_list.len(),
            "routes": routes["routes"].as_array().map(|a| a.len()).unwrap_or(0),
            "docker_containers": docker["containers"].as_array().map(|a| a.len()).unwrap_or(0),
            "docker_running": docker["running"].as_u64().unwrap_or(0),
            "services_running": svc["running_count"].as_u64().unwrap_or(0),
            "listeners": svc["listening"].as_array().map(|a| a.len()).unwrap_or(0),
            "leases": dhcp["dnsmasq"]["lease_count"].as_u64().unwrap_or(0),
            "web_apps": svc["web_listeners"].as_array().map(|a| a.len()).unwrap_or(0),
            "forwards": nat["nft"]["managed"]["rules"].as_array().map(|a| a.len()).unwrap_or(0),
        },
        "wan": {
            "default_dev": routes["default_dev"],
            "default_gw": routes["default_gw"],
        },
        "entry": {
            "lan_ips": lan_ips,
            "wan_ips": wan_ips,
        },
        "health": {
            "nft": nat["nft"]["present"],
            "dnsmasq": dhcp["dnsmasq"]["running"],
            "docker": docker["present"],
            "forward_policy": nat["summary"]["forward_policy"],
            "masquerade": nat["summary"]["masquerade"],
        },
        "web_listeners": svc["web_listeners"],
    }))
    .into_response()
}

async fn h_interfaces(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let (net, nmb, routes) = blocking(move || {
        (
            discovery::net::interfaces(mode),
            discovery::nm::bundle(mode),
            discovery::net::routes(mode),
        )
    })
    .await;
    Json(json!({
        "interfaces": net["interfaces"],
        "default_devs": net["default_devs"],
        "nm": nmb,
        "default_gw": routes["default_gw"],
        "default_dev": routes["default_dev"],
    }))
    .into_response()
}

async fn h_connection(Path(uuid): Path<String>, State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    if uuid.contains("..") || uuid.contains('/') {
        return err(StatusCode::BAD_REQUEST, "非法 uuid").into_response();
    }
    let mode = state.mode;
    let v = blocking(move || discovery::nm::connection_detail(mode, &uuid)).await;
    Json(v).into_response()
}

async fn h_routes(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let (routes, nmb) = blocking(move || (discovery::net::routes(mode), discovery::nm::bundle(mode))).await;
    Json(json!({
        "routes": routes["routes"],
        "rules": routes["rules"],
        "default_gw": routes["default_gw"],
        "default_dev": routes["default_dev"],
        "connections": nmb["connections"],
    }))
    .into_response()
}

async fn h_nat(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::nat::bundle(mode)).await;
    Json(v).into_response()
}

async fn h_dhcp(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::dhcpdns::bundle(mode)).await;
    Json(v).into_response()
}

async fn h_services(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::services::bundle(mode)).await;
    Json(v).into_response()
}

async fn h_docker(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::docker::bundle(mode)).await;
    Json(v).into_response()
}

async fn h_packages(Query(q): Query<HashMap<String, String>>, State(state): State<Shared>, headers: HeaderMap) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::packages::packages(mode)).await;
    Json(v).into_response()
}

async fn h_update_check(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::update::check(mode)).await;
    Json(v).into_response()
}

async fn h_system(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let mode = state.mode;
    let v = blocking(move || discovery::tasks::tasks(mode)).await;
    Json(v).into_response()
}

async fn h_audit(State(state): State<Shared>, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    if let Err(r) = check(&state, &headers, &q.get("token").cloned()) {
        return r;
    }
    let limit: usize = q.get("limit").and_then(|l| l.parse().ok()).unwrap_or(100);
    Json(json!({
        "entries": state.audit_tail(limit.min(500)),
        "backups": state.backup_list().into_iter().rev().take(100).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PlanReq {
    op: String,
    #[serde(default)]
    params: Value,
}

async fn h_plan(State(state): State<Shared>, headers: HeaderMap, body: Json<PlanReq>) -> Response {
    if let Err(r) = check(&state, &headers, &None) {
        return r;
    }
    let st = state.clone();
    let op = body.op.clone();
    let params = body.params.clone();
    let plan = blocking(move || ops::build_plan(&st, &op, &params)).await;
    match plan {
        Ok(mut p) => {
            let id = state.put_plan(p.clone());
            p.id = id;
            Json(json!(p)).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, &e).into_response(),
    }
}

#[derive(Deserialize)]
struct ApplyReq {
    plan_id: String,
    #[serde(default)]
    confirm: bool,
}

async fn h_apply(State(state): State<Shared>, headers: HeaderMap, body: Json<ApplyReq>) -> Response {
    if let Err(r) = check(&state, &headers, &None) {
        return r;
    }
    let Some(plan) = state.get_plan(&body.plan_id) else {
        return err(StatusCode::NOT_FOUND, "计划不存在或已过期，请重新生成").into_response();
    };
    if plan.may_disconnect && !body.confirm {
        return err(StatusCode::FORBIDDEN, "该操作可能中断连接，需要 confirm=true").into_response();
    }
    let st = state.clone();
    let res: ApplyResult = backend::apply_plan(&st, &plan).await;
    state.drop_plan(&plan.id);
    Json(json!(res)).into_response()
}

#[derive(Deserialize)]
struct RollbackReq {
    apply_id: String,
}

async fn h_rollback(State(state): State<Shared>, headers: HeaderMap, body: Json<RollbackReq>) -> Response {
    if let Err(r) = check(&state, &headers, &None) {
        return r;
    }
    let st = state.clone();
    match backend::rollback_run(&st, &body.apply_id).await {
        Ok(res) => Json(json!(res)).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e.to_string()).into_response(),
    }
}

// ---------- static ----------

async fn h_static(uri: axum::http::Uri) -> Response {
    let path = uri.path();
    serve_file(path).unwrap_or_else(|| err(StatusCode::NOT_FOUND, "not found").into_response())
}

async fn h_root() -> Response {
    serve_file("index.html").unwrap_or_else(|| err(StatusCode::NOT_FOUND, "not found").into_response())
}

fn serve_file(path: &str) -> Option<Response> {
    let path = path.trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };
    // disallow traversal
    if path.contains("..") {
        return None;
    }
    let file = WEB.get_file(path)?;
    let mime = match path.rsplit('.').next().unwrap_or("") {
        "html" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" => "application/javascript; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "json" => "application/json",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    let mut resp = Response::new(axum::body::Body::from(file.contents().to_vec()));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        mime.parse().unwrap(),
    );
    // SPA: html/js/css no-cache (frontend is embedded in the binary anyway),
    // other assets (images/fonts) short cache
    let cache = if path.ends_with(".html") || path.ends_with(".js") || path.ends_with(".css") {
        "no-cache"
    } else {
        "max-age=300"
    };
    resp.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        cache.parse().unwrap(),
    );
    Some(resp)
}

pub fn app(state: Shared) -> Router {
    Router::new()
        .route("/", get(h_root))
        .route("/api/status", get(h_status))
        .route("/api/detection", get(h_detection))
        .route("/api/overview", get(h_overview))
        .route("/api/interfaces", get(h_interfaces))
        .route("/api/nm/connection/{uuid}", get(h_connection))
        .route("/api/routes", get(h_routes))
        .route("/api/nat", get(h_nat))
        .route("/api/dhcp", get(h_dhcp))
        .route("/api/services", get(h_services))
        .route("/api/system", get(h_system))
        .route("/api/update/check", get(h_update_check))
        .route("/api/docker", get(h_docker))
        .route("/api/packages", get(h_packages))
        .route("/api/audit", get(h_audit))
        .route("/api/plan", post(h_plan))
        .route("/api/apply", post(h_apply))
        .route("/api/rollback", post(h_rollback))
        .fallback(get(h_static))
        .with_state(state)
}

/// Re-export for main.
pub type AppShared = Arc<AppState>;
