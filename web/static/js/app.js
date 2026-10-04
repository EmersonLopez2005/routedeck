/* RouteDeck core: api client, hash router, modal, toast, plan pipeline */
(function () {
  "use strict";

  const RD = (window.RD = {});

  // ---------- state ----------
  RD.state = {
    status: null,
    token: localStorage.getItem("rd_token") || "",
    route: "overview",
    timer: null,
    history: { cpu: [], rx: [], tx: [], mem: [] },
  };

  // ---------- utils ----------
  const $ = (sel, el) => (el || document).querySelector(sel);
  const $$ = (sel, el) => Array.from((el || document).querySelectorAll(sel));

  RD.$ = $;
  RD.$$ = $$;

  RD.esc = (s) =>
    String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");

  RD.fmtBytes = (n) => {
    n = Number(n) || 0;
    if (n < 1024) return n + " B";
    const u = ["KB", "MB", "GB", "TB", "PB"];
    let i = -1;
    do {
      n /= 1024;
      i++;
    } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n >= 100 ? 0 : n >= 10 ? 1 : 2) + " " + u[i];
  };

  RD.fmtBps = (b) => {
    b = Number(b) || 0;
    if (b < 1000) return b + " bps";
    if (b < 1e6) return (b / 1e3).toFixed(1) + " kbps";
    if (b < 1e9) return (b / 1e6).toFixed(2) + " Mbps";
    return (b / 1e9).toFixed(2) + " Gbps";
  };

  RD.fmtUptime = (s) => {
    s = Number(s) || 0;
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d > 0) return d + "天 " + h + "小时";
    if (h > 0) return h + "小时 " + m + "分";
    return m + "分 " + (s % 60) + "秒";
  };

  RD.fmtAgo = (secs) => {
    secs = Number(secs) || 0;
    if (secs <= 0) return "已过期";
    if (secs < 60) return secs + "秒";
    if (secs < 3600) return Math.floor(secs / 60) + "分钟";
    if (secs < 86400) return Math.floor(secs / 3600) + "小时";
    return Math.floor(secs / 86400) + "天";
  };

  RD.riskText = (r) => ({ low: "低", medium: "中", high: "高" }[r] || r);

  // ---------- api ----------
  async function api(path, opts) {
    opts = opts || {};
    const headers = Object.assign({ "Content-Type": "application/json" }, opts.headers || {});
    if (RD.state.token) headers["X-Auth-Token"] = RD.state.token;
    let resp;
    try {
      resp = await fetch(path, Object.assign({}, opts, { headers }));
    } catch (e) {
      throw new Error("网络错误: " + e.message);
    }
    if (resp.status === 401) {
      const t = prompt("需要访问令牌（安装时生成于 data-dir/token）：");
      if (t) {
        RD.state.token = t.trim();
        localStorage.setItem("rd_token", RD.state.token);
        return api(path, opts);
      }
      throw new Error("未授权");
    }
    let data = null;
    try {
      data = await resp.json();
    } catch (e) {
      /* ignore */
    }
    if (!resp.ok) {
      const msg = (data && data.error) || "HTTP " + resp.status;
      throw new Error(msg);
    }
    return data;
  }

  RD.api = api;
  RD.get = (p) => api(p);
  RD.post = (p, body) =>
    api(p, { method: "POST", body: JSON.stringify(body || {}) });

  // ---------- toast ----------
  RD.toast = (msg, kind) => {
    const root = $("#toastRoot");
    const el = document.createElement("div");
    el.className = "toast " + (kind || "");
    el.innerHTML = RD.esc(msg);
    root.appendChild(el);
    setTimeout(() => {
      el.style.transition = ".3s";
      el.style.opacity = "0";
      el.style.transform = "translateX(30px)";
      setTimeout(() => el.remove(), 320);
    }, kind === "err" ? 5200 : 3000);
  };

  // ---------- modal ----------
  let modalOnClose = null;
  RD.modal = (html, onClose) => {
    const root = $("#modalRoot");
    $("#modalBox").innerHTML = html;
    root.hidden = false;
    modalOnClose = onClose || null;
  };
  RD.closeModal = () => {
    $("#modalRoot").hidden = true;
    $("#modalBox").innerHTML = "";
    if (modalOnClose) {
      const f = modalOnClose;
      modalOnClose = null;
      f();
    }
  };
  RD.modalHead = (title, right) =>
    `<div class="m-head"><div class="m-title">${title}</div>
     ${right || '<button class="m-x" onclick="RD.closeModal()">×</button>'}</div>`;

  // ---------- plan pipeline (核心安全流程) ----------
  // 1) buildPlan  2) 展示确认（命令/警告/风险）  3) apply  4) 结果+回滚
  RD.confirmPlan = async (op, params, opts) => {
    opts = opts || {};
    let plan;
    try {
      plan = await RD.post("/api/plan", { op, params });
    } catch (e) {
      RD.toast("生成计划失败: " + e.message, "err");
      return null;
    }
    const riskCls = "risk risk-" + plan.risk;
    const cmds = plan.commands
      .map(
        (c) =>
          `<div class="cmd"><span class="p">$ </span>${RD.esc(
            c.argv.map(shellQuote).join(" ")
          )}\n<span class="p"># ${RD.esc(c.desc)}</span></div>`
      )
      .join("");
    const files = plan.files
      .map(
        (f) =>
          `<div class="cmd"><span class="p">file→ </span>${RD.esc(f.path)}\n<span class="p"># ${RD.esc(
            f.desc
          )}${f.expect_sha ? " · 校验 sha256" : ""}</span></div>`
      )
      .join("");
    const warns = plan.warnings
      .map((w) => `<div class="warn-item${plan.may_disconnect ? " danger" : ""}"><span>⚠</span><span>${RD.esc(w)}</span></div>`)
      .join("");
    const disconnect = plan.may_disconnect
      ? `<div class="warn-item danger"><span>⛔</span><span><b>高风险：</b>该操作承载默认路由/管理连接，应用后可能立即断开连接。请确保有备用入口。</span></div>
         <label class="f-check"><input type="checkbox" id="ackDisc"><span>我已核对参数，并理解连接可能中断</span></label>`
      : "";

    RD.modal(`
      ${RD.modalHead(
        `${RD.esc(plan.title)} <span class="${riskCls}">RISK ${RD.riskText(plan.risk).toUpperCase()}</span>`
      )}
      <div class="m-body">
        <div class="small muted">${RD.esc(plan.description || "")}</div>
        ${warns ? `<div class="warn-list">${warns}</div>` : ""}
        ${plan.commands.length ? `<div class="small muted">将执行 ${plan.commands.length} 条命令：</div>${cmds}` : ""}
        ${files ? `<div class="small muted">将写入 ${plan.files.length} 个文件（已自动备份）：</div>${files}` : ""}
        ${disconnect}
        <div class="small muted">执行前自动快照，失败自动回滚；成功后仍可一键回滚。</div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="btnApplyPlan">${opts.applyLabel || "执行变更"}</button>
      </div>
    `);

    $("#btnApplyPlan").onclick = async () => {
      if (plan.may_disconnect) {
        const ack = $("#ackDisc");
        if (!ack || !ack.checked) {
          RD.toast("请先勾选确认框", "err");
          return;
        }
      }
      const btn = $("#btnApplyPlan");
      btn.disabled = true;
      btn.textContent = "执行中…";
      try {
        const res = await RD.post("/api/apply", {
          plan_id: plan.id,
          confirm: plan.may_disconnect,
        });
        RD.showApplyResult(res, opts);
      } catch (e) {
        RD.toast("执行失败: " + e.message, "err");
        btn.disabled = false;
        btn.textContent = "执行变更";
      }
    };
    return plan;
  };

  function shellQuote(a) {
    return /[\s"']/.test(a) ? "'" + a.replace(/'/g, "'\\''") + "'" : a;
  }

  RD.showApplyResult = (res, opts) => {
    opts = opts || {};
    const okIcon = `<svg class="ico ok" viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>`;
    const badIcon = `<svg class="ico fail" viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>`;
    const steps = res.steps
      .map(
        (s) => `<div class="step">${s.ok ? okIcon : badIcon}
          <div class="txt"><b>${RD.esc(s.desc)}</b>
          ${s.argv ? `<div class="sub">${RD.esc(s.argv.join(" "))}</div>` : ""}
          ${s.stderr ? `<div class="sub" style="color:#fca5a5">${RD.esc(s.stderr)}</div>` : ""}
          </div></div>`
      )
      .join("");
    const statusMap = {
      applied: ["✓ 已应用", "chip-ok"],
      rolled_back: ["↺ 已回滚（原变更失败）", "chip-warn"],
      partial: ["△ 部分完成，请检查", "chip-warn"],
      failed: ["× 失败", "chip-bad"],
    };
    const [txt, cls] = statusMap[res.status] || [res.status, "chip"];
    const canRollback = res.rollback_available;
    RD.modal(`
      ${RD.modalHead(`执行结果 <span class="chip ${cls}">${txt}</span>`)}
      <div class="m-body">
        ${res.error ? `<div class="warn-list"><div class="warn-item danger"><span>×</span><span>${RD.esc(res.error)}</span></div></div>` : ""}
        <div>${steps || '<div class="empty">无步骤</div>'}</div>
      </div>
      <div class="m-foot">
        ${canRollback ? `<button class="btn btn-danger" id="btnRollback">回滚本次变更</button>` : ""}
        <button class="btn btn-primary" id="btnCloseRes">完成</button>
      </div>
    `);
    $("#btnCloseRes").onclick = () => {
      RD.closeModal();
      if (opts.onDone) opts.onDone(res);
      RD.refresh();
    };
    if (canRollback) {
      $("#btnRollback").onclick = async () => {
        if (!confirm("确认回滚刚才的变更？")) return;
        try {
          const r = await RD.post("/api/rollback", { apply_id: res.apply_id });
          RD.toast(r.status === "rolled_back" ? "已回滚" : "回滚状态: " + r.status, r.status === "rolled_back" ? "ok" : "err");
          RD.showApplyResult(r, opts);
        } catch (e) {
          RD.toast("回滚失败: " + e.message, "err");
        }
      };
    }
  };

  // ---------- sparkline ----------
  RD.spark = (canvas, values, color) => {
    if (!canvas || !values.length) return;
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth || 300;
    const h = canvas.clientHeight || 64;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    const ctx = canvas.getContext("2d");
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(...values, 1);
    const min = Math.min(...values, 0);
    const span = max - min || 1;
    const px = (i) => (i / Math.max(values.length - 1, 1)) * (w - 4) + 2;
    const py = (v) => h - 6 - ((v - min) / span) * (h - 14);
    // fill
    const g = ctx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, color + "55");
    g.addColorStop(1, color + "00");
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
    ctx.lineTo(px(values.length - 1), h);
    ctx.lineTo(px(0), h);
    ctx.closePath();
    ctx.fillStyle = g;
    ctx.fill();
    // line
    ctx.beginPath();
    values.forEach((v, i) => (i ? ctx.lineTo(px(i), py(v)) : ctx.moveTo(px(i), py(v))));
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.8;
    ctx.lineJoin = "round";
    ctx.stroke();
  };

  RD.pushHist = (arr, v, maxLen) => {
    arr.push(Number(v) || 0);
    while (arr.length > (maxLen || 60)) arr.shift();
  };

  // ---------- router ----------
  const routes = {};
  RD.registerRoute = (name, def) => (routes[name] = def);

  const ROUTE_META = {
    overview: ["总览", "路由器实时状态 · 只读发现"],
    interfaces: ["接口", "链路 / 地址 / NetworkManager 连接"],
    routes: ["路由", "内核路由表与策略规则"],
    nat: ["NAT · 防火墙", "端口转发与转发放行（托管表 routedeck）"],
    dhcp: ["DHCP · DNS", "租约 / 静态绑定 / 上游解析"],
    services: ["服务 · 软件", "软件入口 / 监听端口 / systemd / Docker / 已装软件"],
    audit: ["审计 · 备份", "全部变更记录与文件快照"],
    detection: ["检测报告", "安装期只读识别结果"],
    system: ["系统 · 任务", "立即重启 / systemd 定时任务"],
  };

  async function navigate() {
    const hash = (location.hash || "#/overview").replace("#/", "");
    const name = routes[hash] ? hash : "overview";
    RD.state.route = name;
    $$("#nav .nav-item").forEach((a) =>
      a.classList.toggle("active", a.dataset.route === name)
    );
    const [t, s] = ROUTE_META[name] || ["RouteDeck", ""];
    $("#pageTitle").textContent = t;
    $("#pageSub").textContent = s;
    if (RD.state.timer) {
      clearInterval(RD.state.timer);
      RD.state.timer = null;
    }
    const view = $("#view");
    view.innerHTML = '<div class="loading">加载中…</div>';
    try {
      await routes[name].render(view);
      if (routes[name].interval) {
        RD.state.timer = setInterval(() => {
          routes[name].render(view, true).catch(() => {});
        }, routes[name].interval);
      }
    } catch (e) {
      view.innerHTML = `<div class="loading">加载失败：${RD.esc(e.message)}</div>`;
    }
  }

  RD.navigate = navigate;
  RD.refresh = () => navigate();

  // ---------- topbar ----------
  async function loadStatus() {
    try {
      const st = await RD.get("/api/status");
      RD.state.status = st;
      const badge = $("#modeBadge");
      badge.textContent = st.mode === "mock" ? "MOCK 演示" : "LIVE 实机";
      badge.className = "chip chip-mode " + st.mode;
      $("#hostBadge").innerHTML = `<b>${RD.esc(st.hostname)}</b> · ${RD.esc(
        (st.os || "").replace("Debian GNU/Linux ", "Debian ")
      )}`;
      $("#brandVer").textContent = "v" + st.version;
    } catch (e) {
      $("#modeBadge").textContent = "离线";
      $("#modeBadge").className = "chip chip-bad";
    }
  }

  // ---------- boot ----------
  RD.start = () => {
    window.addEventListener("hashchange", navigate);
    $("#btnRefresh").onclick = () => {
      RD.refresh();
      RD.toast("已刷新", "ok");
    };
    $("#modalBackdrop").onclick = RD.closeModal;
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !$("#modalRoot").hidden) RD.closeModal();
    });
    loadStatus();
    setInterval(loadStatus, 30000);
    navigate();
  };
})();
