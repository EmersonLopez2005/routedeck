pub mod ops;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A command step inside a plan. All argv are executed directly (no shell).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CmdStep {
    pub argv: Vec<String>,
    pub desc: String,
}

/// A file mutation inside a plan. Content is complete file content (not a diff).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStep {
    pub path: String,
    pub content: String,
    /// sha256 of the file content observed at plan time; apply aborts if changed since.
    pub expect_sha: Option<String>,
    /// backup id captured at plan time when file already existed.
    pub backup_id: Option<String>,
    /// true when the file did not exist at plan time (rollback removes it).
    pub created: bool,
    pub desc: String,
}

/// One undo action. `Plan.rollback` lists steps in UNDO order:
/// restoring the exact state captured at plan time (making undo idempotent
/// even when apply failed halfway).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RollbackStep {
    /// Run this argv (e.g. `nmcli connection up ...`, `systemctl reload dnsmasq`).
    Cmd { argv: Vec<String>, desc: String },
    /// Restore a previously captured file (None => delete the created file).
    FileRestore { path: String, backup_id: Option<String>, desc: String },
    /// Delete an rd: comment-marked rule from a specific chain.
    NftDeleteByComment {
        family: String,
        table: String,
        chain: String,
        comment: String,
        desc: String,
    },
    /// Set nmcli keys back to plan-time values.
    NmRestoreKeys {
        connection: String,
        keys: Vec<(String, String)>,
        desc: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub id: String,
    pub op: String,
    pub title: String,
    pub description: String,
    /// low | medium | high
    pub risk: String,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub commands: Vec<CmdStep>,
    #[serde(default)]
    pub files: Vec<FileStep>,
    /// UNDO steps, executed in listed order on rollback.
    #[serde(default)]
    pub rollback: Vec<RollbackStep>,
    /// True when applying may disrupt the connectivity carrying the default route / SSH.
    #[serde(default)]
    pub may_disconnect: bool,
    #[serde(default)]
    pub created_ms: u64,
}

impl Plan {
    pub fn new(op: &str, title: &str, risk: &str) -> Self {
        Plan {
            id: String::new(),
            op: op.to_string(),
            title: title.to_string(),
            description: String::new(),
            risk: risk.to_string(),
            warnings: vec![],
            commands: vec![],
            files: vec![],
            rollback: vec![],
            may_disconnect: false,
            created_ms: 0,
        }
    }
}

/// Result of executing a plan.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyResult {
    pub apply_id: String,
    pub plan_id: String,
    pub op: String,
    pub status: String, // applied | failed | rolled_back | partial
    pub steps: Vec<ApplyStepResult>,
    pub rollback_available: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApplyStepResult {
    pub desc: String,
    pub argv: Option<Vec<String>>,
    pub path: Option<String>,
    pub code: i32,
    pub ok: bool,
    pub stderr: String,
    pub stdout_tail: String,
}

/// Tiny sha256 (FIPS 180-4) — no external deps. Returns lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }
    h.iter().map(|x| format!("{:08x}", x)).collect()
}

pub fn sha256_str(s: &str) -> String {
    sha256_hex(s.as_bytes())
}

fn tail(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.len() <= n {
        return t.to_string();
    }
    let mut i = t.len() - n;
    while i < t.len() && !t.is_char_boundary(i) {
        i += 1;
    }
    format!("…{}", &t[i..])
}

/// Execute a plan. Files first (sha precondition + backup), then commands.
/// On failure the FULL declared undo list runs (idempotent: restores plan-time state).
pub async fn apply_plan(state: &crate::state::Shared, plan: &Plan) -> ApplyResult {
    use crate::util;
    let apply_id = util::short_id("a");
    let mut steps: Vec<ApplyStepResult> = Vec::new();
    let mut failure: Option<String> = None;
    let mock = state.mode == crate::state::Mode::Mock;

    for f in &plan.files {
        if f.path.contains("..") {
            failure = Some(format!("非法路径: {}", f.path));
            break;
        }
        let current = std::fs::read(&f.path).ok();
        let existed = current.is_some();
        // sha precondition only matters when we will really write; mock never touches disk
        if !mock {
            if let Some(expect) = &f.expect_sha {
                let cur_sha = current.as_ref().map(|b| sha256_hex(b)).unwrap_or_default();
                if &cur_sha != expect {
                    failure = Some(format!(
                        "文件 {} 自计划生成后已被其他进程修改，已中止（请重新生成计划）",
                        f.path
                    ));
                    break;
                }
            }
        }
        if mock {
            steps.push(ApplyStepResult {
                desc: format!("(mock) 写入 {}", f.path),
                argv: None,
                path: Some(f.path.clone()),
                code: 0,
                ok: true,
                stderr: String::new(),
                stdout_tail: "mock".into(),
            });
            continue;
        }
        let backup_id = if existed {
            Some(
                f.backup_id
                    .clone()
                    .unwrap_or_else(|| state.backup_write(&f.path, current.as_deref().unwrap_or(&[]), "apply")),
            )
        } else {
            None
        };
        let _ = backup_id; // real backup for undo lives in plan.rollback FileRestore
        if let Err(e) = std::fs::write(&f.path, &f.content) {
            failure = Some(format!("写入 {} 失败: {}", f.path, e));
            break;
        }
        steps.push(ApplyStepResult {
            desc: f.desc.clone(),
            argv: None,
            path: Some(f.path.clone()),
            code: 0,
            ok: true,
            stderr: String::new(),
            stdout_tail: String::new(),
        });
    }

    if failure.is_none() {
        for c in &plan.commands {
            if mock {
                steps.push(ApplyStepResult {
                    desc: c.desc.clone(),
                    argv: Some(c.argv.clone()),
                    path: None,
                    code: 0,
                    ok: true,
                    stderr: String::new(),
                    stdout_tail: "mock".into(),
                });
                continue;
            }
            match util::exec(&c.argv) {
                Ok(out) => {
                    let ok = out.ok();
                    steps.push(ApplyStepResult {
                        desc: c.desc.clone(),
                        argv: Some(c.argv.clone()),
                        path: None,
                        code: out.code,
                        ok,
                        stderr: tail(&out.stderr, 600),
                        stdout_tail: tail(&out.stdout, 600),
                    });
                    if !ok {
                        failure = Some(format!("步骤失败: {}", c.desc));
                        break;
                    }
                }
                Err(e) => {
                    steps.push(ApplyStepResult {
                        desc: c.desc.clone(),
                        argv: Some(c.argv.clone()),
                        path: None,
                        code: -1,
                        ok: false,
                        stderr: e.to_string(),
                        stdout_tail: String::new(),
                    });
                    failure = Some(format!("步骤执行异常: {}", e));
                    break;
                }
            }
        }
    }

    let mut status = if failure.is_some() { "failed" } else { "applied" };
    if failure.is_some() && !plan.rollback.is_empty() {
        let rb = run_rollback_steps(state, &plan.rollback).await;
        let all_ok = rb.iter().all(|r| r.ok);
        steps.extend(rb);
        status = if all_ok { "rolled_back" } else { "partial" };
    }

    let result = ApplyResult {
        apply_id: apply_id.clone(),
        plan_id: plan.id.clone(),
        op: plan.op.clone(),
        status: status.into(),
        steps,
        rollback_available: status == "applied" && !plan.rollback.is_empty(),
        error: failure.clone(),
    };

    state.audit_append(&serde_json::json!({
        "ts": util::ts_human(),
        "ts_ms": util::now_ms(),
        "apply_id": apply_id,
        "plan_id": plan.id,
        "op": plan.op,
        "title": plan.title,
        "risk": plan.risk,
        "mode": state.mode.as_str(),
        "status": result.status,
        "error": failure,
        "commands": plan.commands.iter().map(|c| c.argv.join(" ")).collect::<Vec<_>>(),
        "files": plan.files.iter().map(|f| f.path.clone()).collect::<Vec<_>>(),
    }));

    if result.status == "applied" && !plan.rollback.is_empty() {
        let path = state.data_dir.join("runs").join(format!("{}.json", apply_id));
        let payload = serde_json::json!({
            "apply_id": apply_id,
            "plan_id": plan.id,
            "op": plan.op,
            "title": plan.title,
            "ts": util::ts_human(),
            "rollback": plan.rollback,
        });
        let _ = std::fs::write(path, serde_json::to_string(&payload).unwrap_or_default());
    }

    result
}

/// Execute undo steps IN ORDER (they are authored in undo order).
pub async fn run_rollback_steps(state: &crate::state::Shared, steps: &[RollbackStep]) -> Vec<ApplyStepResult> {
    let mock = state.mode == crate::state::Mode::Mock;
    let mut out = Vec::new();
    for rb in steps {
        let mut push = |desc: String, argv: Option<Vec<String>>, path: Option<String>, code: i32, ok: bool, stderr: String, stdout_tail: String| {
            out.push(ApplyStepResult { desc, argv, path, code, ok, stderr, stdout_tail });
        };
        match rb {
            RollbackStep::Cmd { argv, desc } => {
                if mock {
                    push(format!("(mock) {}", desc), Some(argv.clone()), None, 0, true, String::new(), "mock".into());
                    continue;
                }
                match crate::util::exec(argv) {
                    Ok(o) => push(
                        desc.clone(),
                        Some(argv.clone()),
                        None,
                        o.code,
                        o.ok(),
                        tail(&o.stderr, 400),
                        tail(&o.stdout, 400),
                    ),
                    Err(e) => push(desc.clone(), Some(argv.clone()), None, -1, false, e.to_string(), String::new()),
                }
            }
            RollbackStep::FileRestore { path, backup_id, desc } => {
                if mock {
                    push(format!("(mock) {}", desc), None, Some(path.clone()), 0, true, String::new(), "mock".into());
                    continue;
                }
                let res: Result<(), String> = match backup_id {
                    Some(id) => match state.backup_read(id) {
                        Some(bytes) => std::fs::write(path, bytes).map_err(|e| e.to_string()),
                        None => Err(format!("备份 {} 不存在", id)),
                    },
                    None => match std::fs::remove_file(path) {
                        Ok(()) => Ok(()),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(e) => Err(e.to_string()),
                    },
                };
                match res {
                    Ok(()) => push(desc.clone(), None, Some(path.clone()), 0, true, String::new(), String::new()),
                    Err(e) => push(desc.clone(), None, Some(path.clone()), 1, false, e, String::new()),
                }
            }
            RollbackStep::NftDeleteByComment { family, table, chain, comment, desc } => {
                if mock {
                    push(format!("(mock) {}", desc), None, None, 0, true, String::new(), "mock".into());
                    continue;
                }
                match ops::nft_delete_by_comment(family, table, chain, comment) {
                    Ok(d) => push(d, None, None, 0, true, String::new(), String::new()),
                    Err(e) => push(desc.clone(), None, None, 1, false, e.to_string(), String::new()),
                }
            }
            RollbackStep::NmRestoreKeys { connection, keys, desc } => {
                if mock {
                    push(format!("(mock) {}", desc), None, None, 0, true, String::new(), "mock".into());
                    continue;
                }
                match ops::nm_restore_keys(connection, keys) {
                    Ok(()) => push(desc.clone(), None, None, 0, true, String::new(), String::new()),
                    Err(e) => push(desc.clone(), None, None, 1, false, e.to_string(), String::new()),
                }
            }
        }
    }
    out
}

pub async fn rollback_run(state: &crate::state::Shared, apply_id: &str) -> anyhow::Result<ApplyResult> {
    if apply_id.contains('/') || apply_id.contains("..") {
        anyhow::bail!("非法 apply_id");
    }
    let path = state.data_dir.join("runs").join(format!("{}.json", apply_id));
    let text = std::fs::read_to_string(&path)
        .map_err(|_| anyhow::anyhow!("找不到可回滚的执行记录: {}", apply_id))?;
    let v: Value = serde_json::from_str(&text)?;
    let steps: Vec<RollbackStep> = serde_json::from_value(v.get("rollback").cloned().unwrap_or(Value::Array(vec![])))?;
    let results = run_rollback_steps(state, &steps).await;
    let all_ok = results.iter().all(|r| r.ok);
    let result = ApplyResult {
        apply_id: crate::util::short_id("r"),
        plan_id: v.get("plan_id").and_then(|x| x.as_str()).unwrap_or("").to_string(),
        op: v.get("op").and_then(|x| x.as_str()).unwrap_or("rollback").to_string(),
        status: if all_ok { "rolled_back" } else { "partial" }.into(),
        steps: results,
        rollback_available: false,
        error: if all_ok { None } else { Some("部分回滚步骤失败".into()) },
    };
    state.audit_append(&serde_json::json!({
        "ts": crate::util::ts_human(),
        "ts_ms": crate::util::now_ms(),
        "apply_id": result.apply_id,
        "plan_id": result.plan_id,
        "op": "rollback",
        "title": format!("回滚 {}", apply_id),
        "risk": "high",
        "mode": state.mode.as_str(),
        "status": result.status,
        "error": result.error,
    }));
    std::fs::remove_file(&path).ok();
    Ok(result)
}
