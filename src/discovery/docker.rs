use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

fn label(labels: &str, key: &str) -> String {
    // docker ps Labels field: "k=v,k2=v2"
    for part in labels.split(',') {
        if let Some(v) = part.strip_prefix(&format!("{}=", key)) {
            return v.to_string();
        }
    }
    String::new()
}

pub fn bundle(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::docker();
    }

    if !util::has_bin("docker") {
        return json!({"present": false, "reason": "docker 命令不存在"});
    }
    let ver = util::exec(&util::argv(&["docker", "version", "--format", "{{.Server.Version}}"]));
    let Some(ver) = ver.ok() else {
        return json!({"present": false, "reason": "docker 守护进程不可达（未运行或无权限）"});
    };
    if !ver.ok() {
        return json!({"present": false, "reason": format!("docker: {}", ver.stderr.trim())});
    }

    let ps = util::exec(&util::argv(&[
        "docker", "ps", "-a", "--format", "{{json .}}",
    ]))
    .map(|o| o.stdout)
    .unwrap_or_default();
    let mut containers = vec![];
    let mut projects: std::collections::BTreeMap<String, Value> = std::collections::BTreeMap::new();
    for line in ps.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        let labels = v.get("Labels").and_then(|x| x.as_str()).unwrap_or("");
        let project = label(labels, "com.docker.compose.project");
        let workdir = label(labels, "com.docker.compose.project.working_dir");
        if !project.is_empty() {
            let e = projects.entry(project.clone()).or_insert_with(|| {
                json!({"name": project, "workdir": workdir, "count": 0, "running": 0})
            });
            e["count"] = json!(e["count"].as_u64().unwrap_or(0) + 1);
            if v.get("State").and_then(|x| x.as_str()) == Some("running") {
                e["running"] = json!(e["running"].as_u64().unwrap_or(0) + 1);
            }
        }
        containers.push(json!({
            "id": v.get("ID").and_then(|x| x.as_str()).unwrap_or(""),
            "names": v.get("Names").and_then(|x| x.as_str()).unwrap_or(""),
            "image": v.get("Image").and_then(|x| x.as_str()).unwrap_or(""),
            "state": v.get("State").and_then(|x| x.as_str()).unwrap_or(""),
            "status": v.get("Status").and_then(|x| x.as_str()).unwrap_or(""),
            "ports": v.get("Ports").and_then(|x| x.as_str()).unwrap_or(""),
            "created": v.get("CreatedAt").and_then(|x| x.as_str()).unwrap_or(""),
            "labels": labels,
            "project": project,
        }));
    }

    let imgs = util::exec(&util::argv(&["docker", "images", "--format", "{{json .}}"]))
        .map(|o| o.stdout)
        .unwrap_or_default();
    let mut images = vec![];
    for line in imgs.lines() {
        let Ok(v) = serde_json::from_str::<Value>(line) else { continue };
        images.push(json!({
            "id": v.get("ID").and_then(|x| x.as_str()).unwrap_or(""),
            "repository": v.get("Repository").and_then(|x| x.as_str()).unwrap_or(""),
            "tag": v.get("Tag").and_then(|x| x.as_str()).unwrap_or(""),
            "size": v.get("Size").and_then(|x| x.as_str()).unwrap_or(""),
            "created": v.get("CreatedSince").and_then(|x| x.as_str()).unwrap_or(""),
        }));
    }

    json!({
        "present": true,
        "version": ver.stdout.trim(),
        "containers": containers,
        "images": images,
        "projects": projects.values().collect::<Vec<_>>(),
        "running": containers.iter().filter(|c| c["state"] == "running").count(),
    })
}
