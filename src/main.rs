mod api;
mod backend;
mod discovery;
mod state;
mod util;

use state::{AppState, Mode};
use std::path::PathBuf;

fn print_help() {
    println!(
        "routedeck {} — 非侵入式 Debian 路由器 WebUI

用法:
  routedeck serve [选项]          启动 Web 面板（默认命令）
  routedeck detect [选项]         只读检测：打印系统识别报告，不做任何修改
  routedeck version               打印版本

serve 选项:
  --bind <ip>        监听地址（默认 0.0.0.0）
  --port <n>         监听端口（默认 8090）
  --token <t>        访问令牌；未指定时读取 --data-dir/token；都无则不限制（仅建议在可信局域网）
  --data-dir <path>  数据目录（备份/审计），默认 /var/lib/routedeck
  --mock             强制使用演示数据（非 Linux 环境自动启用）
  --detect-only      等价于 detect

安全承诺: 安装与检测阶段不修改任何网络配置；所有变更必须经 WebUI 逐条确认后执行，
执行前自动备份并生成可回滚计划。",
        env!("CARGO_PKG_VERSION")
    );
}

struct Args {
    cmd: String,
    bind: String,
    port: u16,
    token: Option<String>,
    data_dir: Option<String>,
    mock: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        cmd: "serve".into(),
        bind: "0.0.0.0".into(),
        port: 8090,
        token: None,
        data_dir: None,
        mock: false,
    };
    let raw: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < raw.len() {
        let a = raw[i].as_str();
        match a {
            "serve" | "detect" | "version" | "help" => {
                args.cmd = a.to_string();
            }
            "--bind" => {
                i += 1;
                if let Some(v) = raw.get(i) {
                    args.bind = v.clone();
                }
            }
            "--port" => {
                i += 1;
                if let Some(v) = raw.get(i) {
                    args.port = v.parse().unwrap_or(8090);
                }
            }
            "--token" => {
                i += 1;
                if let Some(v) = raw.get(i) {
                    args.token = Some(v.clone());
                }
            }
            "--data-dir" => {
                i += 1;
                if let Some(v) = raw.get(i) {
                    args.data_dir = Some(v.clone());
                }
            }
            "--mock" | "--detect-only" => {
                if a == "--detect-only" {
                    args.cmd = "detect".into();
                } else {
                    args.mock = true;
                }
            }
            "-h" | "--help" => args.cmd = "help".into(),
            "-V" | "--version" => args.cmd = "version".into(),
            other => {
                eprintln!("未知参数: {}", other);
                print_help();
                std::process::exit(2);
            }
        }
        i += 1;
    }
    args
}

fn detect_mode(mock_flag: bool) -> Mode {
    if mock_flag {
        return Mode::Mock;
    }
    if cfg!(windows) {
        return Mode::Mock;
    }
    // On Linux: verify basic tooling exists; without `ip` this cannot be a router host.
    if !util::has_bin("ip") {
        eprintln!("警告: 未找到 `ip` 命令，切换到演示模式（--mock 可显式指定）");
        return Mode::Mock;
    }
    Mode::Live
}

fn main() {
    let args = parse_args();
    match args.cmd.as_str() {
        "help" => {
            print_help();
            return;
        }
        "version" => {
            println!("routedeck {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        "detect" => {
            let mode = detect_mode(args.mock);
            let report = discovery::detection(mode);
            println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            // save snapshot alongside future data dir
            let data_dir = PathBuf::from(
                args.data_dir
                    .clone()
                    .unwrap_or_else(|| default_data_dir().to_string_lossy().to_string()),
            );
            std::fs::create_dir_all(&data_dir).ok();
            let _ = std::fs::write(
                data_dir.join("detection.json"),
                serde_json::to_string_pretty(&report).unwrap_or_default(),
            );
            return;
        }
        "serve" => {}
        other => {
            eprintln!("未知命令: {}", other);
            print_help();
            std::process::exit(2);
        }
    }

    let mode = detect_mode(args.mock);
    let data_dir = PathBuf::from(
        args.data_dir
            .clone()
            .unwrap_or_else(|| default_data_dir().to_string_lossy().to_string()),
    );
    std::fs::create_dir_all(&data_dir).ok();

    // token resolution: --token > data-dir/token file > none
    let mut token = args.token.clone();
    if token.is_none() {
        let t = std::fs::read_to_string(data_dir.join("token"))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        if !t.is_empty() {
            token = Some(t);
        }
    }

    let state = AppState::new(mode, data_dir.clone(), token.clone());

    // save first-run detection snapshot (read-only)
    let report = discovery::detection(mode);
    if state.load_detection().is_none() {
        state.save_detection(&report);
    }

    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    runtime.block_on(async move {
        let app = api::app(state.clone());
        let addr = format!("{}:{}", args.bind, args.port);
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("无法监听 {}: {}", addr, e);
                std::process::exit(1);
            }
        };
        println!("RouteDeck v{} 已启动", env!("CARGO_PKG_VERSION"));
        println!("  模式:   {}", mode.as_str());
        println!("  地址:   http://{}", addr);
        println!("  数据:   {}", data_dir.display());
        println!(
            "  令牌:   {}",
            match &token {
                Some(t) if !t.is_empty() => "已启用（请求需带 X-Auth-Token）",
                _ => "未启用（受限网络请用 --token 或 data-dir/token）",
            }
        );
        println!("  原则:   安装与检测不改配置；变更仅经 WebUI 确认后执行");
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .expect("server error");
    });
}

fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("./routedeck-data")
    } else {
        PathBuf::from("/var/lib/routedeck")
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c().await.ok();
    };
    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    println!("\n收到退出信号，正在停止…");
}
