use crate::state::Mode;
use crate::util;
use serde_json::{json, Value};

/// Installed packages via dpkg (read-only). Returns name+version pairs.
pub fn packages(mode: Mode) -> Value {
    if mode == Mode::Mock {
        return crate::discovery::mock::packages();
    }
    let out = util::exec(&util::argv(&[
        "dpkg-query",
        "-W",
        "-f=${binary:Package}\\t${Version}\\t${db:Status-Abbrev}\\n",
    ]));
    let Ok(out) = out else {
        return json!({"total": 0, "items": [], "error": "dpkg-query 不可用"});
    };
    if !out.ok() {
        return json!({"total": 0, "items": [], "error": out.stderr.trim()});
    }
    let mut items = vec![];
    for line in out.stdout.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        if !f[2].starts_with("ii") {
            continue; // only installed
        }
        items.push(json!({"name": f[0], "version": f[1]}));
    }
    json!({"total": items.len(), "items": items})
}
