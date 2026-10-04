/* RouteDeck views — page renderers */
(function () {
  "use strict";
  const { $, $$, esc, get, post, toast, modal, closeModal, modalHead, confirmPlan, refresh, spark, pushHist, fmtBytes, fmtBps, fmtUptime, fmtAgo } = RD;

  const el = (h) => h;
  const card = (title, sub, right, body) => `
    <div class="card">
      <div class="card-h">
        <div class="card-t">${title}${sub ? ` <span class="card-sub">${esc(sub)}</span>` : ""}</div>
        ${right || ""}
      </div>
      ${body}
    </div>`;

  const table = (cols, rows) => {
    // rows may be an array of <tr> strings or an already-joined string
    const body = Array.isArray(rows) ? rows.join("") : rows || "";
    if (!body) return `<div class="empty">暂无数据</div>`;
    return `<div style="overflow:auto"><table class="tb">
      <thead><tr>${cols
        .map((c) => {
          const title = typeof c === "string" ? c : c.t || "";
          return `<th class="${(typeof c === "string" ? "" : c.cls) || ""}">${title}</th>`;
        })
        .join("")}</tr></thead>
      <tbody>${body}</tbody></table></div>`;
  };

  const ipChips = (arr) =>
    (arr || []).map((a) => `<span class="iface-addr mono">${esc(a)}</span>`).join(" ");

  // ================= 总览 =================
  async function renderOverview(view, isTick) {
    const ov = await get("/api/overview");
    const h = RD.state.history;
    const memPct =
      ov.host.mem_total_kb > 0
        ? Math.round((1 - ov.host.mem_avail_kb / ov.host.mem_total_kb) * 100)
        : 0;
    if (isTick || !h.cpu.length) {
      pushHist(h.cpu, ov.net.cpu_pct || 0);
      pushHist(h.rx, ov.net.rx_bps || 0);
      pushHist(h.tx, ov.net.tx_bps || 0);
      pushHist(h.mem, memPct);
    }

    const cpuCls = ov.net.cpu_pct > 85 ? "warn" : "";
    const counts = ov.counts || {};
    const wanUp = (ov.interfaces || []).find((i) => i.is_default);

    const stat = (k, v, unit, d, cls) => `
      <div class="card stat">
        <div class="k">${k}</div>
        <div class="v ${cls || ""}">${v}${unit ? `<small>${unit}</small>` : ""}</div>
        <div class="d">${d || ""}</div>
      </div>`;

    const healthChips = [
      ov.health.nft ? `<span class="chip chip-ok"><span class="dot"></span>nftables</span>` : `<span class="chip chip-bad">nftables 缺失</span>`,
      ov.health.dnsmasq ? `<span class="chip chip-ok"><span class="dot"></span>dnsmasq</span>` : `<span class="chip chip-warn">dnsmasq 未运行</span>`,
      ov.health.docker ? `<span class="chip chip-ok"><span class="dot"></span>Docker</span>` : `<span class="chip">Docker —</span>`,
      `<span class="chip ${ov.health.forward_policy === "drop" ? "chip-warn" : "chip-info"}">forward ${esc(ov.health.forward_policy)}</span>`,
      ov.health.masquerade ? `<span class="chip chip-ok">MASQUERADE ✓</span>` : `<span class="chip chip-warn">未检测到 MASQUERADE</span>`,
    ].join("");

    const ifaceRows = (ov.interfaces || [])
      .map(
        (i) => `<tr>
        <td><span class="st ${i.up ? "on" : "off"}"></span> <b>${esc(i.name)}</b></td>
        <td><span class="chip chip-cat">${esc(i.category)}</span></td>
        <td class="mono">${ipChips(i.addr4) || '<span class="muted">—</span>'}</td>
        <td>${i.is_default ? '<span class="chip chip-info">默认出口</span>' : ""}</td>
      </tr>`
      )
      .join("");

    const webRows = (ov.web_listeners || [])
      .map(
        (w) => `<tr>
        <td class="mono">${esc(w.local)}</td>
        <td><b>${esc(w.process || "?")}</b></td>
        <td class="muted mono">${esc(w.proto)}</td>
        <td class="right"><a class="btn btn-sm btn-ghost" href="${w.local.replace("0.0.0.0", location.hostname).replace("127.0.0.1", location.hostname)}" target="_blank" rel="noopener">打开</a></td>
      </tr>`
      )
      .join("");

    view.innerHTML = `
      <div class="section">
        <div class="grid g4">
          ${stat("CPU", (ov.net.cpu_pct ?? 0).toFixed(0), "%", esc(ov.host.cpu_model || ""), cpuCls)}
          ${stat("内存", memPct, "%", `${fmtBytes(ov.host.mem_total_kb * 1024)} · 可用 ${fmtBytes(ov.host.mem_avail_kb * 1024)}`)}
          ${stat("运行时间", fmtUptime(ov.host.uptime_secs), "", `负载 ${((ov.host.load || [])[0] ?? 0).toFixed(2)} / ${((ov.host.load || [])[1] ?? 0).toFixed(2)} / ${((ov.host.load || [])[2] ?? 0).toFixed(2)}`)}
          ${stat("默认出口", esc(wanUp ? wanUp.name : ov.wan.default_dev || "—"), "", `gw ${esc(ov.wan.default_gw || "—")}`)}
        </div>
      </div>

      <div class="section">
        <div class="card pad-s">
          <div class="row" style="flex-wrap:wrap;gap:8px">
            <span class="chip chip-info">访问入口</span>
            ${(() => {
              const port = location.port ? ":" + location.port : "";
              const lan = (ov.entry && ov.entry.lan_ips) || [];
              const wan = (ov.entry && ov.entry.wan_ips) || [];
              const chips = lan.map(
                (ip) =>
                  `<a class="chip mono" href="http://${esc(ip)}${port}/" target="_blank" rel="noopener" title="LAN 口地址，局域网内推荐使用">http://${esc(ip)}${port}/</a>`
              );
              const wchips = wan.map(
                (ip) => `<span class="chip mono muted" title="WAN 口地址，仅公网/远程访问时使用">${esc(ip)}</span>`
              );
              return (
                chips.join("") +
                (wchips.length
                  ? `<span class="muted small">WAN:</span>${wchips.join("")}`
                  : "") +
                (chips.length ? "" : '<span class="muted small">未检测到 LAN 侧 IPv4</span>')
              );
            })()}
            <span class="spacer"></span>
            <span class="muted small">局域网请用 LAN 地址访问；WAN 地址仅在远程管理时使用</span>
          </div>
        </div>
      </div>

      <div class="section">
        <div class="grid g3">
          ${card("实时流量", "入站 / 出站 · 最近 3 分钟", `<div class="row"><span class="chip">↓ ${fmtBps(ov.net.rx_bps)}</span><span class="chip">↑ ${fmtBps(ov.net.tx_bps)}</span></div>`, `
            <canvas class="spark" id="spkRx" style="height:74px"></canvas>
            <canvas class="spark" id="spkTx" style="height:50px"></canvas>`)}
          ${card("健康度", "关键组件", "", `<div class="healthy">${healthChips}</div>
            <div class="kv" style="margin-top:13px">
              <span class="k">接口</span><span class="v">${counts.interfaces}</span>
              <span class="k">路由条目</span><span class="v">${counts.routes}</span>
              <span class="k">端口转发</span><span class="v">${counts.forwards}</span>
              <span class="k">DHCP 租约</span><span class="v">${counts.leases}</span>
            </div>`)}
          ${card("资产计数", "面板已识别", "", `
            <div class="grid g-auto-s">
              <div class="card pad-s stat"><div class="k">Web 应用</div><div class="v">${counts.web_apps}</div></div>
              <div class="card pad-s stat"><div class="k">Docker 容器</div><div class="v">${counts.docker_running}<small>/${counts.docker_containers}</small></div></div>
              <div class="card pad-s stat"><div class="k">运行服务</div><div class="v">${counts.services_running}</div></div>
              <div class="card pad-s stat"><div class="k">监听端口</div><div class="v">${counts.listeners}</div></div>
            </div>`)}
        </div>
      </div>

      <div class="section">
        <div class="grid g2">
          ${card("接口速览", "状态 / 地址", `<a class="btn btn-sm" href="#/interfaces">管理接口 →</a>`, table(
            [{ t: "接口" }, { t: "类型" }, { t: "IPv4" }, { t: "" }],
            ifaceRows
          ))}
          ${card("已识别 WebUI 项目", "监听端口发现", `<a class="btn btn-sm" href="#/services">全部服务 →</a>`, table(
            [{ t: "监听" }, { t: "进程" }, { t: "协议" }, { cls: "right", t: "" }],
            webRows
          ))}
        </div>
      </div>`;

    // sparklines
    requestAnimationFrame(() => {
      spark($("#spkRx"), h.rx, "#22d3ee");
      spark($("#spkTx"), h.tx, "#818cf8");
    });
  }

  // ================= 接口 =================
  async function renderInterfaces(view) {
    const d = await get("/api/interfaces");
    const nm = d.nm || {};
    const devs = nm.devices || [];
    const conns = nm.connections || [];

    const cards = (d.interfaces || [])
      .map((i) => {
        const dev = devs.find((x) => x.device === i.name);
        return `<div class="card pad-s iface-card">
          <div class="iface-top">
            <div class="iface-name"><span class="st ${i.up ? "on" : "off"}"></span>${esc(i.name)}
              <span class="chip chip-cat">${esc(i.category)}</span>
              ${i.is_default ? '<span class="chip chip-info">默认</span>' : ""}
            </div>
            <span class="muted small">${esc(i.operstate)}</span>
          </div>
          <div>${ipChips(i.addr4) || '<span class="muted small">无 IPv4</span>'}</div>
          ${i.addr6 && i.addr6.length ? `<div class="muted small mono">${esc(i.addr6.join(" "))}</div>` : ""}
          <div class="iface-meta">
            <span>MTU ${i.mtu}</span>
            ${i.vlan_id != null ? `<span>VLAN ${i.vlan_id}</span>` : ""}
            ${i.parent ? `<span>父口 ${esc(i.parent)}</span>` : ""}
            <span>邻居 ${i.neighbors ?? 0}</span>
          </div>
          <div class="iface-meta">
            <span>↓ ${fmtBytes(i.rx_bytes)}</span><span>↑ ${fmtBytes(i.tx_bytes)}</span>
          </div>
          ${dev ? `<div class="muted small">NM: ${esc(dev.connection)} · ${esc(dev.state)}</div>` : ""}
        </div>`;
      })
      .join("");

    const nmChip = nm.nm && nm.nm.running
      ? `<span class="chip chip-ok"><span class="dot"></span>NetworkManager 运行中</span>`
      : nm.nm && nm.nm.present
      ? `<span class="chip chip-warn">NetworkManager 未运行</span>`
      : `<span class="chip chip-bad">未检测到 NetworkManager</span>`;

    // live interface names — never hardcoded (Debian predictable naming: enp1s0/ens1p0/…)
    const ifNames = (d.interfaces || [])
      .filter((i) => i.category !== "loopback")
      .map((i) => i.name);

    const connRows = conns
      .map((c) => {
        const dev = devs.find((x) => x.device === c.device);
        const connected = dev && (dev.state === "connected" || dev.state === "activating");
        const isPppoe = c.type === "pppoe";
        return `<tr>
          <td><b>${esc(c.name)}</b></td>
          <td class="mono small">${esc(c.type)}</td>
          <td class="mono">${esc(c.device || "—")}</td>
          <td>${dev ? `<span class="st ${connected ? "on" : ""}"></span>${esc(dev.state)}` : "—"}</td>
          <td class="right" style="white-space:nowrap">
            <button class="btn btn-sm" data-conn="${esc(c.uuid)}" data-name="${esc(c.name)}">配置 IP</button>
            ${isPppoe ? `
            <button class="btn btn-sm" data-pppoe="${esc(c.uuid)}" data-name="${esc(c.name)}">拨号参数</button>
            <button class="btn btn-sm" data-redial="${esc(c.uuid)}" data-name="${esc(c.name)}">重拨</button>` : ""}
            <button class="btn btn-sm ${connected ? "btn-danger" : ""}" data-link="${esc(c.uuid)}" data-name="${esc(c.name)}" data-action="${connected ? "down" : "up"}">${connected ? "停用" : "启用"}</button>
            <button class="btn btn-sm btn-ghost" data-mtu="${esc(c.uuid)}" data-name="${esc(c.name)}">MTU/MAC</button>
            <button class="btn btn-sm btn-ghost" data-metric="${esc(c.uuid)}" data-name="${esc(c.name)}">优先级</button>
            <button class="btn btn-sm btn-ghost" data-rebind="${esc(c.uuid)}" data-name="${esc(c.name)}">换绑网卡</button>
          </td>
        </tr>`;
      })
      .join("");

    view.innerHTML = `
      <div class="section">
        <div class="row">${nmChip}<span class="chip">${esc((nm.nm || {}).version || "")}</span>
          <span class="chip">网卡 ${ifNames.length} 个（实时检测）</span><span class="spacer"></span>
          <button class="btn btn-primary btn-sm" id="btnCreatePppoe">＋ 创建 PPPoE</button>
          <button class="btn btn-primary btn-sm" id="btnCreateEth">＋ 创建以太网</button>
          <span class="muted small">修改将生成计划 → 确认后执行（自动备份 / 可回滚）</span></div>
      </div>
      <div class="section"><div class="grid g-auto">${cards || '<div class="empty">无接口</div>'}</div></div>
      <div class="section">
        ${card("NetworkManager 连接", "持久化网络配置 · 启停 / 拨号 / MTU / 出口优先级 / 换绑网卡", "", table(
          [{ t: "名称" }, { t: "类型" }, { t: "设备" }, { t: "状态" }, { cls: "right", t: "操作" }],
          connRows
        ))}
      </div>`;

    $("#btnCreatePppoe").onclick = () => createPppoeForm(ifNames);
    $("#btnCreateEth").onclick = () => createEthernetForm(ifNames);
    $$("#view button[data-rebind]").forEach((b) => {
      b.onclick = () => setIfnameForm(b.dataset.rebind, b.dataset.name, ifNames);
    });
    $$("#view button[data-conn]").forEach((b) => {
      b.onclick = () => openConnForm(b.dataset.conn, b.dataset.name);
    });
    $$("#view button[data-pppoe]").forEach((b) => {
      b.onclick = () => openPppoeForm(b.dataset.pppoe, b.dataset.name);
    });
    $$("#view button[data-redial]").forEach((b) => {
      b.onclick = async () => {
        if (!confirm(`断线重拨「${b.dataset.name}」？期间该 WAN 会短暂离线。`)) return;
        await confirmPlan("nm.reconnect", { connection: b.dataset.redial }, { onDone: refresh });
      };
    });
    $$("#view button[data-link]").forEach((b) => {
      b.onclick = async () => {
        const action = b.dataset.action;
        if (action === "down" && !confirm(`停用「${b.dataset.name}」？对应链路将断开。`)) return;
        await confirmPlan("nm.set_link", { connection: b.dataset.link, action }, { onDone: refresh });
      };
    });
    $$("#view button[data-mtu]").forEach((b) => {
      b.onclick = () => setMtuForm(b.dataset.mtu, b.dataset.name);
    });
    $$("#view button[data-metric]").forEach((b) => {
      b.onclick = () => setMetricForm(b.dataset.metric, b.dataset.name);
    });
  }

  // —— 以太网创建（LAN 口 / 第二条 WAN，DHCP 或静态） ——
  function createEthernetForm(ifNames) {
    const opts = (ifNames || []).map((n) => `<option value="${esc(n)}">`).join("");
    modal(`
      ${modalHead("创建以太网连接（LAN 口 / WAN 均可）")}
      <div class="m-body">
        <div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>连接名</label><input id="etName" placeholder="LAN1 / WAN2-DHCP"></div>
            <div class="f-row"><label>物理网卡</label>
              <input id="etIf" list="etIfList" placeholder="如 enp2s0" required>
              <datalist id="etIfList">${opts}</datalist>
              <span class="hint">候选来自实时检测（ip -j link），非硬编码</span>
            </div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>IPv4 获取方式</label>
              <select id="etMethod">
                <option value="auto">DHCP 自动获取</option>
                <option value="manual">静态地址</option>
              </select>
            </div>
            <div class="f-row"><label>出口优先级 metric（可选，1–9999）</label>
              <input id="etMetric" type="number" min="1" max="9999" placeholder="留空=默认 100；备用 WAN 填 200">
            </div>
          </div>
          <div id="etManualBox" style="display:none">
            <div class="f-grid2">
              <div class="f-row"><label>静态地址（CIDR，多个逗号分隔）</label><input id="etAddr" placeholder="192.168.1.1/24"></div>
              <div class="f-row"><label>网关（可选）</label><input id="etGw" placeholder="192.168.1.254"></div>
            </div>
            <div class="f-row"><label>DNS（可选，逗号分隔）</label><input id="etDns" placeholder="223.5.5.5,119.29.29.29"></div>
          </div>
        </div>
        <div class="warn-item danger"><span>⚠</span><span>新连接会立即占用所选网卡。LAN 口接交换机即可做内网；WAN 口请配合「优先级」与 NAT 页 MASQUERADE 组成多 WAN。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="etNext">生成变更计划</button>
      </div>`);
    $("#etMethod").onchange = () => {
      $("#etManualBox").style.display = $("#etMethod").value === "manual" ? "" : "none";
    };
    $("#etNext").onclick = async () => {
      const params = {
        name: $("#etName").value.trim(),
        ifname: $("#etIf").value.trim(),
        method: $("#etMethod").value,
      };
      if (!params.name || !params.ifname) {
        toast("连接名 / 网卡为必填", "err");
        return;
      }
      const metric = $("#etMetric").value;
      if (metric) params.metric = Number(metric);
      if (params.method === "manual") {
        const addr = $("#etAddr").value.trim();
        if (!addr) {
          toast("静态模式需填写地址", "err");
          return;
        }
        params.addresses = addr.split(",").map((s) => s.trim()).filter(Boolean);
        const gw = $("#etGw").value.trim();
        if (gw) params.gateway = gw;
        const dns = $("#etDns").value.trim();
        if (dns) params.dns = dns.split(",").map((s) => s.trim()).filter(Boolean);
      }
      closeModal();
      await confirmPlan("nm.create_ethernet", params, { onDone: refresh });
    };
  }

  // —— 换绑网卡（WAN/LAN 角色互换） ——
  async function setIfnameForm(uuid, name, ifNames) {
    let keys = {};
    try {
      const d = await RD.get("/api/nm/connection/" + encodeURIComponent(uuid));
      keys = (d && d.keys) || {};
    } catch (e) { /* fall through */ }
    const cur = keys["connection.interface-name"] || "";
    const opts = (ifNames || []).map((n) => `<option value="${esc(n)}">`).join("");
    modal(`
      ${modalHead(`换绑网卡 · ${esc(name)}`)}
      <div class="m-body">
        <div class="form">
          <div class="f-row"><label>目标物理网卡</label>
            <input id="riIf" list="riIfList" value="${esc(cur)}" required>
            <datalist id="riIfList">${opts}</datalist>
            <span class="hint">当前绑定: ${esc(cur || "（未绑定）")} · 候选来自实时检测</span>
          </div>
        </div>
        <div class="warn-item danger"><span>⚠</span><span>换绑 = WAN/LAN 角色互换：连接迁移到新网卡并重新激活。原网卡将失去此连接的配置，管理链路可能中断。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="riNext">生成变更计划</button>
      </div>`);
    $("#riNext").onclick = async () => {
      const ifname = $("#riIf").value.trim();
      if (!ifname) {
        toast("目标网卡为必填", "err");
        return;
      }
      if (ifname === cur) {
        toast("目标网卡与当前绑定相同", "err");
        return;
      }
      closeModal();
      await confirmPlan("nm.set_ifname", { connection: uuid, ifname }, { onDone: refresh });
    };
  }

  // —— PPPoE 创建（网卡候选来自实时检测） ——
  function createPppoeForm(ifNames) {
    const opts = (ifNames || []).map((n) => `<option value="${esc(n)}">`).join("");
    modal(`
      ${modalHead("创建 PPPoE 拨号连接")}
      <div class="m-body">
        <div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>连接名</label><input id="peName" placeholder="WAN1-PPPoE"></div>
            <div class="f-row"><label>物理网卡</label>
              <input id="peIf" list="peIfList" placeholder="ppp0 所在网卡，如 enp1s0" required>
              <datalist id="peIfList">${opts}</datalist>
              <span class="hint">候选来自实时检测（ip -j link），非硬编码</span>
            </div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>拨号账号</label><input id="peUser" placeholder="宽带账号"></div>
            <div class="f-row"><label>拨号密码</label><input id="pePass" type="password" placeholder="宽带密码"></div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>ISP 服务名（可选）</label><input id="peSvc" placeholder="多数省份留空"></div>
            <div class="f-row"><label>MTU（可选，576–9000）</label><input id="peMtu" type="number" placeholder="1492"></div>
          </div>
        </div>
        <div class="warn-item danger"><span>⚠</span><span>拨号会立即占用所选网卡。若该网卡承载当前管理连接，执行后会话可能中断。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="peNext">生成变更计划</button>
      </div>`);
    $("#peNext").onclick = async () => {
      const params = {
        name: $("#peName").value.trim(),
        ifname: $("#peIf").value.trim(),
        username: $("#peUser").value.trim(),
      };
      if (!params.name || !params.ifname || !params.username) {
        toast("连接名 / 网卡 / 账号为必填", "err");
        return;
      }
      const pass = $("#pePass").value;
      if (pass) params.password = pass;
      const svc = $("#peSvc").value.trim();
      if (svc) params.service = svc;
      const mtu = $("#peMtu").value;
      if (mtu) params.mtu = Number(mtu);
      closeModal();
      await confirmPlan("nm.create_pppoe", params, { onDone: refresh });
    };
  }

  // —— PPPoE 拨号参数编辑 ——
  async function openPppoeForm(uuid, name) {
    let keys = {};
    try {
      const d = await RD.get("/api/nm/connection/" + encodeURIComponent(uuid));
      keys = (d && d.keys) || {};
    } catch (e) {
      toast("读取连接详情失败: " + e.message, "err");
      return;
    }
    modal(`
      ${modalHead(`PPPoE 拨号参数 · ${esc(name)}`)}
      <div class="m-body">
        <div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>拨号账号</label><input id="pwUser" value="${esc(keys["pppoe.username"] || "")}"></div>
            <div class="f-row"><label>新密码（留空=不改）</label><input id="pwPass" type="password" placeholder="不修改请留空"></div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>ISP 服务名</label><input id="pwSvc" value="${esc(keys["pppoe.service"] || "")}" placeholder="留空=不改"></div>
            <div class="f-row"><label>MTU（ppp.mtu）</label><input id="pwMtu" type="number" value="${esc(keys["ppp.mtu"] || "")}" placeholder="留空=不改"></div>
          </div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>保存后自动重拨生效。旧密码 nmcli 默认不可读，回滚只能还原其它字段。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="pwNext">生成变更计划</button>
      </div>`);
    $("#pwNext").onclick = async () => {
      const params = { connection: uuid };
      const u = $("#pwUser").value.trim();
      if (u) params.username = u;
      const p = $("#pwPass").value;
      if (p) params.password = p;
      const sv = $("#pwSvc").value.trim();
      if (sv) params.service = sv;
      const m = $("#pwMtu").value;
      if (m) params.mtu = Number(m);
      if (Object.keys(params).length === 1) {
        toast("没有要修改的字段", "err");
        return;
      }
      closeModal();
      await confirmPlan("nm.update_pppoe", params, { onDone: refresh });
    };
  }

  // —— MTU / 克隆 MAC ——
  async function setMtuForm(uuid, name) {
    let keys = {};
    try {
      const d = await RD.get("/api/nm/connection/" + encodeURIComponent(uuid));
      keys = (d && d.keys) || {};
    } catch (e) { /* fall through with empty keys */ }
    const curMtu = keys["802-3.ethernet.mtu"] || keys["ppp.mtu"] || keys["802-11.mtu"] || "";
    modal(`
      ${modalHead(`修改 MTU / MAC · ${esc(name)}`)}
      <div class="m-body">
        <div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>MTU（68–9000，留空=不改）</label><input id="muVal" type="number" value="${esc(curMtu)}" placeholder="1500"></div>
            <div class="f-row"><label>克隆 MAC（留空=不改）</label><input id="muMac" value="${esc(keys["802-3.ethernet.cloned-mac-address"] || "")}" placeholder="aa:bb:cc:dd:ee:ff"></div>
          </div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>按连接类型自动选择 mtu 键（ethernet / ppp / wifi）；保存后重激活连接生效。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="muNext">生成变更计划</button>
      </div>`);
    $("#muNext").onclick = async () => {
      const params = { connection: uuid };
      const m = $("#muVal").value;
      if (m) params.mtu = Number(m);
      const mac = $("#muMac").value.trim();
      if (mac) params.mac = mac;
      if (Object.keys(params).length === 1) {
        toast("没有要修改的字段", "err");
        return;
      }
      closeModal();
      await confirmPlan("nm.set_mtu", params, { onDone: refresh });
    };
  }

  // —— 双 WAN 出口优先级 ——
  async function setMetricForm(uuid, name) {
    let keys = {};
    try {
      const d = await RD.get("/api/nm/connection/" + encodeURIComponent(uuid));
      keys = (d && d.keys) || {};
    } catch (e) { /* fall through */ }
    const nd = keys["ipv4.never-default"] === "yes";
    modal(`
      ${modalHead(`出口优先级 · ${esc(name)}`)}
      <div class="m-body">
        <div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>route-metric（1–9999，越小越优先）</label>
              <input id="mtVal" type="number" min="1" max="9999" value="${esc(keys["ipv4.route-metric"] || "")}" placeholder="100 / 200">
            </div>
            <div class="f-row"><label>不作为默认出口</label>
              <select id="mtNd">
                <option value="" ${keys["ipv4.never-default"] == null ? "selected" : ""}>不修改</option>
                <option value="yes" ${nd ? "selected" : ""}>是（never-default=yes）</option>
                <option value="no" ${keys["ipv4.never-default"] != null && !nd ? "selected" : ""}>否（never-default=no）</option>
              </select>
            </div>
          </div>
        </div>
        <div class="warn-item danger"><span>⚠</span><span>双 WAN 场景下调整 metric 会切换默认出口。若当前管理链路走该 WAN，确认另一条可达后再执行。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="mtNext">生成变更计划</button>
      </div>`);
    $("#mtNext").onclick = async () => {
      const params = { connection: uuid };
      const m = $("#mtVal").value;
      if (m) params.metric = Number(m);
      const ndv = $("#mtNd").value;
      if (ndv) params.never_default = ndv === "yes";
      if (Object.keys(params).length === 1) {
        toast("没有要修改的字段", "err");
        return;
      }
      closeModal();
      await confirmPlan("nm.set_metric", params, { onDone: refresh });
    };
  }

  async function openConnForm(uuid, name) {
    let keys = {};
    try {
      const d = await RD.get("/api/nm/connection/" + encodeURIComponent(uuid));
      keys = (d && d.keys) || {};
    } catch (e) {
      toast("读取连接详情失败: " + e.message, "err");
      return;
    }
    const method = keys["ipv4.method"] || "auto";
    modal(`
      ${modalHead(`配置连接 · ${esc(name)}`)}
      <div class="m-body">
        <div class="form">
          <div class="f-row">
            <label>IPv4 方法</label>
            <select id="cfMethod">
              <option value="manual" ${method === "manual" ? "selected" : ""}>static · 静态地址</option>
              <option value="auto" ${method === "auto" ? "selected" : ""}>auto · DHCP 自动获取</option>
            </select>
          </div>
          <div class="f-row">
            <label>地址（CIDR，逗号分隔）</label>
            <input id="cfAddr" value="${esc(keys["ipv4.addresses"] || "")}" placeholder="192.168.1.1/24">
            <span class="hint">静态模式必填；DHCP 模式留空</span>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>网关</label><input id="cfGw" value="${esc(keys["ipv4.gateway"] || "")}" placeholder="留空清除"></div>
            <div class="f-row"><label>DNS（逗号分隔）</label><input id="cfDns" value="${esc(keys["ipv4.dns"] || "")}" placeholder="223.5.5.5,119.29.29.29"></div>
          </div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>当前值将作为回滚基线快照；执行前所有命令都会展示。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="cfNext">生成变更计划</button>
      </div>
    `);
    $("#cfNext").onclick = async () => {
      const params = {
        connection: uuid,
        method: $("#cfMethod").value,
        addresses: $("#cfAddr").value.split(",").map((s) => s.trim()).filter(Boolean),
        gateway: $("#cfGw").value.trim(),
        dns: $("#cfDns").value.split(",").map((s) => s.trim()).filter(Boolean),
      };
      closeModal();
      await confirmPlan("nm.apply_ip", params, { onDone: refresh });
    };
  }

  // ================= 路由 =================
  async function renderRoutes(view) {
    const d = await get("/api/routes");
    const rows = (d.routes || [])
      .map((r) => {
        const def = r.dst === "default";
        return `<tr>
          <td class="mono"><b class="${def ? "" : ""}">${esc(r.dst)}</b>${def ? ' <span class="chip chip-info">默认</span>' : ""}</td>
          <td class="mono">${esc(r.gateway || "—")}</td>
          <td class="mono">${esc(r.dev || "—")}</td>
          <td class="mono">${esc(r.table)}</td>
          <td class="right">${r.metric || ""}</td>
          <td class="muted small">${esc(r.protocol || "")} ${esc(r.scope || "")}</td>
        </tr>`;
      })
      .join("");

    const ruleRows = (d.rules || [])
      .map(
        (r) => `<tr>
        <td class="right mono">${r.priority}</td><td class="mono">${esc(r.table)}</td>
        <td>${esc(r.action)}</td><td class="mono">${esc(r.src || "—")}</td>
      </tr>`
      )
      .join("");

    const connOpts = (d.connections || [])
      .map((c) => `<option value="${esc(c.uuid)}">${esc(c.name)}${c.device ? " (" + esc(c.device) + ")" : ""}</option>`)
      .join("");

    view.innerHTML = `
      <div class="section">
        <div class="row">
          <span class="chip">默认网关 <b>${esc(d.default_gw || "—")}</b></span>
          <span class="chip">出口 <b>${esc(d.default_dev || "—")}</b></span>
          <span class="spacer"></span>
          <button class="btn btn-primary btn-sm" id="btnAddRoute">＋ 添加静态路由</button>
        </div>
      </div>
      <div class="section">
        ${card("内核路由表", "ip route show table all", "", table(
          [{ t: "目标" }, { t: "下一跳" }, { t: "设备" }, { t: "表" }, { cls: "right", t: "metric" }, { t: "来源" }],
          rows
        ))}
      </div>
      <div class="section">
        ${card("策略规则", "ip rule show", "", table(
          [{ cls: "right", t: "优先级" }, { t: "表" }, { t: "动作" }, { t: "源" }],
          ruleRows
        ))}
      </div>`;

    $("#btnAddRoute").onclick = () => {
      modal(`
        ${modalHead("添加静态路由")}
        <div class="m-body">
          <div class="form">
            <div class="f-row"><label>所属 NM 连接</label><select id="rtConn">${connOpts}</select></div>
            <div class="f-grid2">
              <div class="f-row"><label>目标网络</label><input id="rtDst" placeholder="10.0.0.0/8 或 default"></div>
              <div class="f-row"><label>下一跳网关</label><input id="rtGw" placeholder="192.168.1.254，直连可留空"></div>
            </div>
            <div class="f-row"><label>metric（可选）</label><input id="rtMetric" type="number" placeholder="如 100"></div>
          </div>
        </div>
        <div class="m-foot">
          <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
          <button class="btn btn-primary" id="rtNext">生成变更计划</button>
        </div>`);
      $("#rtNext").onclick = async () => {
        const params = {
          connection: $("#rtConn").value,
          dst: $("#rtDst").value.trim(),
          gw: $("#rtGw").value.trim(),
        };
        const m = $("#rtMetric").value;
        if (m) params.metric = Number(m);
        closeModal();
        await confirmPlan("nm.add_route", params, { onDone: refresh });
      };
    };
  }

  // ================= NAT / 防火墙 =================
  async function renderNat(view) {
    const [d, ifd] = await Promise.all([get("/api/nat"), get("/api/interfaces")]);
    const s = d.summary || {};
    const managed = (d.nft && d.nft.managed) || { available: false, rules: [] };
    const rules = managed.rules || [];
    // live interface names (never hardcoded — Debian uses predictable names)
    const ifNames = (ifd.interfaces || [])
      .filter((i) => i.category !== "loopback")
      .map((i) => i.name);

    const managedRows = rules
      .map(
        (r) => `<tr>
        <td>${esc(r.desc || r.comment)}</td>
        <td class="mono small">${esc(r.chain)}</td>
        <td class="mono">${r.handle}</td>
        <td class="right">
          <button class="btn btn-sm btn-danger" data-del="${esc(r.id)}" data-chain="${esc(r.chain)}">删除</button>
        </td>
      </tr>`
      )
      .join("");

    // chain selector for accept rules
    const chainOpts = ((d.nft && d.nft.tables) || [])
      .flatMap((t) => (t.chains || []).map((c) => ({ t, c })))
      .filter((x) => x.c.hook === "forward" || x.c.hook === "input")
      .map(
        (x) =>
          `<option value="${esc(x.t.family)}|${esc(x.t.name)}|${esc(x.c.name)}">${esc(
            x.t.family + " " + x.t.name + " " + x.c.name
          )} (hook ${esc(x.c.hook)}, policy ${esc(x.c.policy || "-")})</option>`
      )
      .join("");

    const ifOpts = ifNames
      .map((i) => `<option value="${esc(i)}">`)
      .join("");

    // masq toggle rows: managed rd masq rules + system masq ifaces
    const masqIfaces = s.masquerade_ifaces || [];
    const rdMasq = rules.filter((r) => (r.id || "").startsWith("masq-"));
    const masqRows = [...new Set([...masqIfaces, ...rdMasq.map((r) => (r.id || "").slice(5))])]
      .map((ifn) => {
        const on = rdMasq.some((r) => r.id === "masq-" + ifn);
        return `<tr>
          <td class="mono"><b>${esc(ifn)}</b></td>
          <td>${on ? '<span class="chip chip-ok">托管规则 ✓</span>' : '<span class="chip">非托管</span>'}</td>
          <td class="right">
            ${on
              ? `<button class="btn btn-sm btn-danger" data-masq-off="${esc(ifn)}">关闭</button>`
              : `<button class="btn btn-sm" data-masq-on="${esc(ifn)}">开启</button>`}
          </td>
        </tr>`;
      })
      .join("");

    const rawText = d.backend === "nft"
      ? (d.nft.ruleset_text || "")
      : `# iptables-save -t nat\n${(d.iptables && d.iptables.nat_text) || ""}\n\n# iptables-save -t filter\n${(d.iptables && d.iptables.filter_text) || ""}`;

    view.innerHTML = `
      <div class="section">
        <div class="row">
          <span class="chip ${d.backend === "nft" ? "chip-ok" : "chip-warn"}">后端 ${esc(d.backend)}</span>
          <span class="chip ${s.forward_policy === "drop" ? "chip-warn" : "chip-info"}">forward 策略: ${esc(s.forward_policy)}</span>
          <span class="chip ${s.masquerade ? "chip-ok" : "chip-warn"}">${s.masquerade ? "MASQUERADE ✓ " + esc((s.masquerade_ifaces || []).join(",")) : "无 MASQUERADE"}</span>
          <span class="chip">系统 DNAT ${s.dnat_count ?? 0} 条</span>
        </div>
      </div>

      <div class="section">
        <div class="grid g2">
          ${card("托管端口转发", "table inet routedeck · 可增删", `<button class="btn btn-primary btn-sm" id="btnAddFwd">＋ 端口转发</button>`,
            table([{ t: "规则" }, { t: "链" }, { t: "handle" }, { cls: "right", t: "" }], managedRows))}
          ${card("追加放行规则", "写入你现有的 filter 链（只增不改）", `<button class="btn btn-sm" id="btnAddAcc">＋ 放行规则</button>`, `
            <div class="small muted">将匹配的流量追加 accept 规则到指定链尾部，原有规则不受影响；每条规则自带 rd: 标记，可一键删除回滚。</div>
            ${managed.available ? "" : '<div class="warn-item danger"><span>×</span><span>当前系统无 nft，托管写操作不可用（只读展示）。</span></div>'}
            <div class="kv" style="margin-top:10px">
              <span class="k">托管表</span><span class="v">${esc(managed.table || "—")}</span>
              <span class="k">表存在</span><span class="v">${managed.table_exists ? "✓" : "（首次写入时自动创建）"}</span>
              <span class="k">托管规则</span><span class="v">${rules.length}</span>
            </div>`)}
        </div>
      </div>

      <div class="section">
        <div class="grid g2">
          ${card("MASQUERADE（按出口）", "托管 postrouting · 只增删自己的规则",
            `<button class="btn btn-primary btn-sm" id="btnAddDmz">＋ DMZ</button>`,
            (masqRows
              ? table([{ t: "出口" }, { t: "状态" }, { cls: "right", t: "操作" }], masqRows)
              : '<div class="empty">未检测到 masquerade 接口</div>') +
            `<div class="small muted" style="margin-top:8px">仅操作 inet routedeck 表内的 rd:masq 规则；你现有 NAT 规则不受影响。</div>`)}
          ${card("DMZ（全端口转发）", "高风险 · 单主机暴露", "", `
            <div class="small muted">将某 WAN 的全部入站端口转发到一台内网主机（无端口限制的 DNAT）。</div>
            <div class="warn-item danger" style="margin-top:10px"><span>⚠</span><span>DMZ = 全端口暴露。目标主机必须自带防火墙；仅建议在无法逐一映射端口时使用。</span></div>
            <div class="kv" style="margin-top:10px">
              <span class="k">当前 DMZ</span><span class="v">${rules.filter((r) => (r.id || "").startsWith("dmz")).map((r) => esc(r.desc)).join("<br>") || "无"}</span>
            </div>`)}
        </div>
      </div>

      <div class="section">
        ${card("系统规则集（只读）", d.backend === "nft" ? "nft list ruleset" : "iptables-save",
          `<button class="btn btn-sm copy-btn" id="btnCopyRaw">复制</button>`,
          `<div class="raw" id="rawRule">${esc(rawText || "(空)")}</div>`)}
      </div>`;

    if (managed.available !== false) {
      const bAdd = $("#btnAddFwd");
      if (bAdd) bAdd.onclick = addForwardForm;
      const bAcc = $("#btnAddAcc");
      if (bAcc) bAcc.onclick = () => acceptForm(chainOpts, ifOpts);
    }
    const bDmz = $("#btnAddDmz");
    if (bDmz) bDmz.onclick = () => dmzForm(ifNames);
    $$("#view button[data-masq-on]").forEach((b) => {
      b.onclick = () => confirmPlan("nft.set_masquerade", { oif: b.dataset.masqOn, enable: true }, { onDone: refresh });
    });
    $$("#view button[data-masq-off]").forEach((b) => {
      b.onclick = () => confirmPlan("nft.set_masquerade", { oif: b.dataset.masqOff, enable: false }, { onDone: refresh });
    });
    $("#btnCopyRaw").onclick = async () => {
      try {
        await navigator.clipboard.writeText(rawText || "");
        toast("已复制", "ok");
      } catch (e) {
        toast("复制失败", "err");
      }
    };
    $$("#view button[data-del]").forEach((b) => {
      b.onclick = async () => {
        if (!confirm("删除该托管规则？")) return;
        await confirmPlan(
          "nft.del_rule",
          { family: "inet", table: "routedeck", chain: b.dataset.chain, id: b.dataset.del },
          { onDone: refresh }
        );
      };
    });
  }

  async function addForwardForm() {
    const d = await get("/api/interfaces");
    const ifNames = (d.interfaces || []).filter((i) => i.category !== "loopback").map((i) => i.name);
    modal(`
      ${modalHead("添加端口转发 (DNAT)")}
      <div class="m-body">
        <div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>协议</label><select id="fwProto"><option value="tcp">TCP</option><option value="udp">UDP</option></select></div>
            <div class="f-row"><label>入接口（WAN，留空=任意）</label>
              <input id="fwIf" list="ifList" placeholder="ppp0 / eth0">
              <datalist id="ifList">${ifNames.map((n) => `<option value="${esc(n)}">`).join("")}</datalist>
            </div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>外部端口</label><input id="fwPort" type="number" placeholder="8080"></div>
            <div class="f-row"><label>内网地址</label><input id="fwTo" placeholder="192.168.1.10"></div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>内网端口（可选，同外部可留空）</label><input id="fwToPort" type="number" placeholder="80"></div>
            <div class="f-row"><label>备注（可选）</label><input id="fwNote" placeholder="nas-ui"></div>
          </div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>规则将写入 RouteDeck 托管表 inet routedeck，不影响你现有的 nat 规则。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="fwNext">生成变更计划</button>
      </div>`);
    $("#fwNext").onclick = async () => {
      const params = {
        proto: $("#fwProto").value,
        wan_if: $("#fwIf").value.trim(),
        dst_port: Number($("#fwPort").value),
        to_addr: $("#fwTo").value.trim(),
        note: $("#fwNote").value.trim(),
      };
      const tp = $("#fwToPort").value;
      if (tp) params.to_port = Number(tp);
      closeModal();
      await confirmPlan("nft.add_forward", params, { onDone: refresh });
    };
  }

  function acceptForm(chainOpts, ifOpts) {
    if (!chainOpts) {
      toast("未检测到可用 filter 链", "err");
      return;
    }
    modal(`
      ${modalHead("追加转发放行规则")}
      <div class="m-body">
        <div class="form">
          <div class="f-row"><label>目标链</label><select id="acChain">${chainOpts}</select></div>
          <div class="f-grid2">
            <div class="f-row"><label>协议</label><select id="acProto">
              <option value="tcp">TCP</option><option value="udp">UDP</option>
              <option value="icmp">ICMP</option><option value="any">任意</option></select></div>
            <div class="f-row"><label>目标端口（可选）</label><input id="acPort" type="number" placeholder="53"></div>
          </div>
          <div class="f-row"><label>出接口（可选）</label><input id="acOif" list="oifList" placeholder="ppp0"><datalist id="oifList">${ifOpts}</datalist></div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>规则追加到链尾，不修改、不删除任何既有规则。删除仅限本面板添加的 rd: 规则。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="acNext">生成变更计划</button>
      </div>`);
    $("#acNext").onclick = async () => {
      const [family, table, chain] = $("#acChain").value.split("|");
      const params = { family, table, chain, proto: $("#acProto").value, oif: $("#acOif").value.trim() };
      const p = $("#acPort").value;
      if (p) params.port = Number(p);
      closeModal();
      await confirmPlan("nft.add_accept", params, { onDone: refresh });
    };
  }

  function dmzForm(ifNames) {
    modal(`
      ${modalHead("添加 DMZ（全端口转发）")}
      <div class="m-body">
        <div class="form">
          <div class="f-row"><label>入接口（WAN，留空=任意）</label>
            <input id="dzIf" list="dzIfList" placeholder="如 ppp0">
            <datalist id="dzIfList">${(ifNames || []).map((n) => `<option value="${esc(n)}">`).join("")}</datalist>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>内网目标主机</label><input id="dzTo" placeholder="192.168.1.10"></div>
            <div class="f-row"><label>备注（可选）</label><input id="dzNote" placeholder="game-pc"></div>
          </div>
        </div>
        <div class="warn-item danger"><span>⚠</span><span>该主机全部入站端口将暴露到所选 WAN。确保目标主机防火墙仅放行必要端口。</span></div>
      </div>
      <div class="m-foot">
        <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
        <button class="btn btn-primary" id="dzNext">生成变更计划</button>
      </div>`);
    $("#dzNext").onclick = async () => {
      const params = {
        wan_if: $("#dzIf").value.trim(),
        to_addr: $("#dzTo").value.trim(),
        note: $("#dzNote").value.trim(),
      };
      closeModal();
      await confirmPlan("nft.add_dmz", params, { onDone: refresh });
    };
  }

  // ================= DHCP / DNS =================
  async function renderDhcp(view) {
    const d = await get("/api/dhcp");
    const dn = d.dnsmasq || {};
    const ours = dn.our_snippet || {};
    const dns = d.dns || {};

    const leaseRows = (dn.leases || [])
      .map(
        (l) => `<tr>
        <td class="mono">${esc(l.mac)}</td>
        <td class="mono"><b>${esc(l.ip)}</b></td>
        <td>${esc(l.name || "—")}</td>
        <td class="muted small">${fmtAgo(l.remaining_secs)}</td>
        <td class="mono muted small">${esc((l.src || "").replace("/var/lib/", "…/"))}</td>
      </tr>`
      )
      .join("");

    const bindRows = (ours.bindings || [])
      .map(
        (b) => `<tr>
        <td class="mono">${esc(b.mac)}</td>
        <td class="mono"><b>${esc(b.ip)}</b></td>
        <td>${esc(b.name || "—")}</td>
        <td class="right"><button class="btn btn-sm btn-danger" data-delmac="${esc(b.mac)}">删除</button></td>
      </tr>`
      )
      .join("");

    const icsRows = (d.nm_ics || [])
      .map(
        (i) => `<tr><td>${esc(i.name)}</td><td class="mono">${esc(i.device)}</td>
        <td class="mono">${esc(JSON.stringify(i.addresses))}</td></tr>`
      )
      .join("");

    const scope = ours.scope && ours.scope.start ? ours.scope : null;
    const sopts = ours.options || {};
    const hostRows = (ours.hosts || [])
      .map(
        (h) => `<tr>
        <td class="mono"><b>${esc(h.name)}</b></td>
        <td class="mono">${esc(h.ip)}</td>
        <td class="right"><button class="btn btn-sm btn-danger" data-delhost="${esc(h.name)}">删除</button></td>
      </tr>`
      )
      .join("");

    const foreign = d.foreign_ranges || [];
    const icsConflict = (d.nm_ics || []).length > 0;

    view.innerHTML = `
      <div class="section">
        <div class="row">
          <span class="chip ${d.backend !== "none" ? "chip-ok" : "chip-warn"}">DHCP 后端: ${esc(d.backend)}</span>
          <span class="chip ${dn.running ? "chip-ok" : "chip-bad"}">dnsmasq ${dn.running ? "运行中" : "未运行"}</span>
          <span class="chip">租约 ${dn.lease_count ?? 0}</span>
          <span class="chip">上游 ${esc((dn.upstreams || []).join(", ") || "—")}</span>
          <span class="spacer"></span>
          <button class="btn btn-primary btn-sm" id="btnScope">⚙ 作用域与选项</button>
        </div>
        ${icsConflict ? `<div class="warn-item danger" style="margin-top:10px"><span>×</span><span>NM 共享网络 (ICS) 正在提供 DHCP——作用域写入将被后端拒绝，避免双 DHCP 冲突。</span></div>` : ""}
        ${foreign.length ? `<div class="warn-item" style="margin-top:10px"><span>⚠</span><span>其它配置已有 ${foreign.length} 处 dhcp-range：${foreign.map((f) => esc(f.file) + " :: " + esc(f.line)).join(" | ")}。写入前请确认网段不重叠。</span></div>` : ""}
      </div>

      <div class="section">
        <div class="grid g2">
          ${card("DHCP 作用域", "dhcp-range + 下发选项", `<button class="btn btn-sm" id="btnScope2">编辑</button>`, `
            <div class="kv">
              <span class="k">地址池</span><span class="v mono">${scope ? esc(scope.start + " – " + scope.end) : "（未在托管片段声明）"}</span>
              <span class="k">掩码</span><span class="v mono">${scope && scope.netmask ? esc(scope.netmask) : "自动"}</span>
              <span class="k">租期</span><span class="v">${scope && scope.lease ? esc(scope.lease) : "—"}</span>
              <span class="k">网关 (opt 3)</span><span class="v mono">${esc(sopts.gateway || "—")}</span>
              <span class="k">DNS (opt 6)</span><span class="v mono">${esc((sopts.dns || []).join(", ") || "—")}</span>
              <span class="k">域 (opt 15)</span><span class="v">${esc(sopts.domain || "—")}</span>
            </div>`)}
          ${card("本地域名解析", "address=/name/ip · 内网直接用域名访问", `<button class="btn btn-primary btn-sm" id="btnAddHost">＋ 记录</button>`,
            table([{ t: "域名" }, { t: "指向" }, { cls: "right", t: "" }], hostRows))}
        </div>
      </div>

      <div class="section">
        <div class="grid g2">
          ${card("活动租约", "dnsmasq.leases", "", table(
            [{ t: "MAC" }, { t: "IP" }, { t: "主机名" }, { t: "剩余" }, { t: "来源" }],
            leaseRows
          ))}
          ${card("静态绑定", (ours.path || "").replace("/etc/", ""), `<button class="btn btn-primary btn-sm" id="btnAddBind">＋ 静态绑定</button>`,
            table([{ t: "MAC" }, { t: "IP" }, { t: "名称" }, { cls: "right", t: "" }], bindRows))}
        </div>
      </div>

      <div class="section">
        <div class="grid g2">
          ${card("DNS 解析路径", "resolv.conf → 上游", `<button class="btn btn-sm" id="btnUpstream">编辑上游 DNS</button>`, `
            <div class="kv">
              <span class="k">resolv.conf</span><span class="v">${esc(dns.resolv_path || "")}</span>
              ${dns.resolv_target ? `<span class="k">实际指向</span><span class="v">${esc(dns.resolv_target)}</span>` : ""}
              <span class="k">nameserver</span><span class="v">${esc((dns.resolv_nameservers || []).join(", ") || "—")}</span>
              <span class="k">dnsmasq 上游</span><span class="v">${esc((dns.dnsmasq_upstreams || []).join(", ") || "—")}</span>
              <span class="k">来源</span><span class="v">${esc(dns.source || "")}</span>
            </div>
            <div class="small muted" style="margin-top:10px">${dn.conf_dir_included != null ? `conf-dir 已包含: ${esc(dn.conf_dir_included)}` : "⚠ /etc/dnsmasq.conf 未包含 dnsmasq.d —— 首次写入时将自动追加（并备份原文件）"}</div>`)}
          ${card("其它 DHCP 后端", "NM ICS / Kea / ISC", "", `
            ${icsRows ? table([{ t: "连接" }, { t: "设备" }, { t: "地址" }], icsRows) : '<div class="empty">未检测到 NM 共享网络 (ICS)</div>'}
            <div class="row" style="margin-top:10px">
              <span class="chip ${d.kea && d.kea.present ? "chip-ok" : ""}">Kea: ${d.kea && d.kea.present ? "检测到" : "无"}</span>
              <span class="chip ${d.isc && d.isc.present ? "chip-ok" : ""}">ISC dhcpd: ${d.isc && d.isc.present ? "检测到" : "无"}</span>
            </div>`)}
        </div>
      </div>

      <div class="section">
        ${card("托管片段", ours.path || "/etc/dnsmasq.d/routedeck.conf", "",
          `<div class="raw">${esc(ours.content || "(尚未创建 — 执行任一 DHCP 变更时生成)")}</div>`)}
      </div>`;

    $("#btnAddBind").onclick = () => {
      modal(`
        ${modalHead("添加 DHCP 静态绑定")}
        <div class="m-body"><div class="form">
          <div class="f-row"><label>MAC 地址</label><input id="bdMac" placeholder="9c:b6:d8:11:2a:30"></div>
          <div class="f-grid2">
            <div class="f-row"><label>固定 IP</label><input id="bdIp" placeholder="192.168.1.10"></div>
            <div class="f-row"><label>主机名（可选）</label><input id="bdName" placeholder="nas"></div>
          </div>
        </div></div>
        <div class="m-foot">
          <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
          <button class="btn btn-primary" id="bdNext">生成变更计划</button>
        </div>`);
      $("#bdNext").onclick = async () => {
        const params = { mac: $("#bdMac").value.trim(), ip: $("#bdIp").value.trim(), name: $("#bdName").value.trim() };
        closeModal();
        await confirmPlan("dnsmasq.add_binding", params, { onDone: refresh });
      };
    };
    $$("#view button[data-delmac]").forEach((b) => {
      b.onclick = async () => {
        if (!confirm("删除静态绑定 " + b.dataset.delmac + "？")) return;
        await confirmPlan("dnsmasq.del_binding", { mac: b.dataset.delmac }, { onDone: refresh });
      };
    });

    const openScopeForm = () => {
      const sc = scope || { start: "", end: "", netmask: "", lease: "12h" };
      modal(`
        ${modalHead("DHCP 作用域与下发选项")}
        <div class="m-body"><div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>起始地址</label><input id="scStart" value="${esc(sc.start || "")}" placeholder="192.168.1.100"></div>
            <div class="f-row"><label>结束地址</label><input id="scEnd" value="${esc(sc.end || "")}" placeholder="192.168.1.240"></div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>子网掩码（可选）</label><input id="scMask" value="${esc(sc.netmask || "")}" placeholder="255.255.255.0"></div>
            <div class="f-row"><label>租期</label><input id="scLease" value="${esc(sc.lease || "12h")}" placeholder="12h / 30m / infinite"></div>
          </div>
          <div class="f-grid2">
            <div class="f-row"><label>网关（opt 3，可选）</label><input id="scGw" value="${esc(sopts.gateway || "")}" placeholder="192.168.1.1"></div>
            <div class="f-row"><label>域名（opt 15，可选）</label><input id="scDom" value="${esc(sopts.domain || "")}" placeholder="lan"></div>
          </div>
          <div class="f-row"><label>DNS（opt 6，逗号分隔，可选）</label>
            <input id="scDns" value="${esc((sopts.dns || []).join(", "))}" placeholder="223.5.5.5,119.29.29.29"></div>
        </div>
        ${foreign.length ? `<div class="warn-item"><span>⚠</span><span>检测到其它配置已有 dhcp-range，若网段重叠会导致地址池混乱。</span></div>` : ""}
        ${icsConflict ? `<div class="warn-item danger"><span>×</span><span>NM ICS 正在提供 DHCP——后端将拒绝写入。</span></div>` : ""}
        <div class="warn-item"><span>ⓘ</span><span>写入 RouteDeck 托管片段（带备份/回滚），不修改你其它 dnsmasq 配置。</span></div></div>
        <div class="m-foot">
          <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
          <button class="btn btn-primary" id="scNext">生成变更计划</button>
        </div>`);
      $("#scNext").onclick = async () => {
        const params = {
          start: $("#scStart").value.trim(),
          end: $("#scEnd").value.trim(),
          netmask: $("#scMask").value.trim(),
          lease: $("#scLease").value.trim() || "12h",
          gateway: $("#scGw").value.trim(),
          domain: $("#scDom").value.trim(),
          dns: $("#scDns").value.split(",").map((s) => s.trim()).filter(Boolean),
        };
        closeModal();
        await confirmPlan("dnsmasq.set_scope", params, { onDone: refresh });
      };
    };
    $("#btnScope").onclick = openScopeForm;
    $("#btnScope2").onclick = openScopeForm;

    $("#btnAddHost").onclick = () => {
      modal(`
        ${modalHead("添加本地域名解析")}
        <div class="m-body"><div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>域名</label><input id="hsName" placeholder="nas.lan"></div>
            <div class="f-row"><label>指向 IP</label><input id="hsIp" placeholder="192.168.1.10"></div>
          </div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>记录整体替换托管片段中的 address= 列表（现有记录会先带入表单值之外的会保留——本操作为全量提交）。</span></div></div>
        <div class="m-foot">
          <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
          <button class="btn btn-primary" id="hsNext">生成变更计划</button>
        </div>`);
      $("#hsNext").onclick = async () => {
        const hosts = [...(ours.hosts || []), { name: $("#hsName").value.trim(), ip: $("#hsIp").value.trim() }];
        closeModal();
        await confirmPlan("dnsmasq.set_hosts", { hosts }, { onDone: refresh });
      };
    };
    $$("#view button[data-delhost]").forEach((b) => {
      b.onclick = async () => {
        if (!confirm("删除域名记录 " + b.dataset.delhost + "？")) return;
        const hosts = (ours.hosts || []).filter((h) => h.name !== b.dataset.delhost);
        await confirmPlan("dnsmasq.set_hosts", { hosts }, { onDone: refresh });
      };
    });
    $("#btnUpstream").onclick = () => {
      modal(`
        ${modalHead("编辑上游 DNS")}
        <div class="m-body"><div class="form">
          <div class="f-row"><label>上游服务器（逗号分隔）</label>
            <input id="upVal" value="${esc((dns.dnsmasq_upstreams || []).join(", "))}" placeholder="223.5.5.5,119.29.29.29"></div>
        </div>
        <div class="warn-item"><span>ⓘ</span><span>写入 RouteDeck 托管片段；若其他配置也含 server= 将合并生效。</span></div></div>
        <div class="m-foot">
          <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
          <button class="btn btn-primary" id="upNext">生成变更计划</button>
        </div>`);
      $("#upNext").onclick = async () => {
        const servers = $("#upVal").value.split(",").map((s) => s.trim()).filter(Boolean);
        closeModal();
        await confirmPlan("dnsmasq.set_upstreams", { servers }, { onDone: refresh });
      };
    };
  }

  // ================= 服务 · 软件 · Docker =================
  let svcTab = "apps";

  // 常见软件识别：进程名/容器名 → 显示名
  const KNOWN_APPS = {
    qinglong: "青龙面板",
    openclash: "OpenClash",
    grafana: "Grafana",
    prometheus: "Prometheus",
    "uptime-kuma": "Uptime Kuma",
    portainer: "Portainer",
    homer: "Homer",
    nginx: "Nginx",
    caddy: "Caddy",
    pihole: "Pi-hole",
    "pihole-ftl": "Pi-hole",
    transmission: "Transmission",
    qbittorrent: "qBittorrent",
    jellyfin: "Jellyfin",
    emby: "Emby",
    navidrome: "Navidrome",
    homeassistant: "Home Assistant",
    "home assistant": "Home Assistant",
    frps: "FRP 服务端",
    frpc: "FRP 客户端",
    tailscale: "Tailscale",
    syncthing: "Syncthing",
    minio: "MinIO",
    gitlab: "GitLab",
    gitea: "Gitea",
    nextcloud: "Nextcloud",
    vaultwarden: "Vaultwarden",
    umami: "Umami",
    uptime: "Uptime",
    adguardhome: "AdGuard Home",
    node: "Node 服务",
    python3: "Python 服务",
    python: "Python 服务",
  };

  // 从 `0.0.0.0:5700->5700/tcp` 里取宿主端口
  function dockerHostPort(ports) {
    if (!ports) return null;
    for (const part of String(ports).split(",")) {
      const m = part.match(/:(\d+)->/);
      if (m) return Number(m[1]);
    }
    const m2 = String(ports).match(/^(\d+)\/tcp$/);
    return m2 ? Number(m2[1]) : null;
  }

  function drawApps(root, svc, docker) {
    const entries = new Map(); // port -> entry
    const add = (port, name, source, detail) => {
      if (!port || port < 1 || port > 65535) return;
      const prev = entries.get(port);
      if (prev) {
        if (prev.source !== source) prev.detail = prev.detail + " · " + detail;
        return;
      }
      entries.set(port, {
        port,
        name: KNOWN_APPS[String(name).toLowerCase()] || name,
        known: !!KNOWN_APPS[String(name).toLowerCase()],
        source,
        detail,
      });
    };

    for (const l of svc.web_listeners || []) {
      const m = String(l.local).match(/:(\d+)$/);
      if (m) add(Number(m[1]), l.process || "web", "proc", l.local);
    }
    if (docker.present) {
      for (const c of docker.containers || []) {
        if (c.state !== "running") continue;
        const p = dockerHostPort(c.ports);
        if (p) add(p, c.names, "docker", c.image || "");
      }
    }

    const items = [...entries.values()].sort((a, b) => a.port - b.port);
    const cards = items
      .map((e) => {
        const loopback = e.detail.startsWith("127.");
        const href = `${location.protocol}//${location.hostname}:${e.port}/`;
        const src = e.source === "docker" ? '<span class="chip chip-info">Docker</span>' : '<span class="chip chip-cat">进程</span>';
        return `<div class="card" style="padding:14px 16px">
          <div class="row" style="align-items:center">
            <div>
              <div style="font-weight:600">${esc(e.name)} ${e.known ? "" : '<span class="chip">未识别</span>'}</div>
              <div class="muted small mono" style="margin-top:4px">:${e.port} · ${esc(e.detail)} ${src}</div>
            </div>
            <span class="spacer"></span>
            ${loopback ? '<span class="chip chip-warn">仅本机监听</span>' : `<a class="btn btn-primary btn-sm" href="${esc(href)}" target="_blank" rel="noopener">打开 ↗</a>`}
          </div>
        </div>`;
      })
      .join("");

    root.innerHTML = `<div class="section">
      ${card("软件入口", `识别到 ${items.length} 个 Web 入口 · 点击直接在新标签打开`,
        `<span class="muted small">地址使用当前访问域名 + 端口</span>`,
        items.length
          ? `<div class="grid g2" style="gap:12px">${cards}</div>`
          : `<div class="empty">未扫描到 Web 入口</div>`)}
    </div>
    <div class="section">
      ${card("识别依据", "", "",
        `<div class="small muted">来自 <span class="mono">ss</span> 的 Web 监听进程与 Docker 容器端口映射；常见软件（青龙 / OpenClash / Grafana 等）自动显示中文名，其它显示进程名。仅绑定 127.0.0.1 的入口外部无法访问，已标注。</div>`)}
    </div>`;
  }

  async function renderServices(view) {
    const [svc, docker, pkgs] = await Promise.all([
      get("/api/services"),
      get("/api/docker").catch(() => ({ present: false })),
      get("/api/packages").catch(() => ({ total: 0, items: [] })),
    ]);

    const tabs = [
      ["apps", "软件入口"],
      ["listen", "监听端口"],
      ["units", "systemd 服务"],
      ["docker", "Docker"],
      ["packages", "已装软件"],
    ]
      .map(([k, t]) => `<button class="tab ${svcTab === k ? "active" : ""}" data-tab="${k}">${t}</button>`)
      .join("");

    view.innerHTML = `<div class="section"><div class="tabs" id="svcTabs">${tabs}</div></div><div id="svcBody"></div>`;

    const body = $("#svcBody");
    const draw = () => {
      if (svcTab === "apps") drawApps(body, svc, docker);
      else if (svcTab === "listen") drawListen(body, svc);
      else if (svcTab === "units") drawUnits(body, svc);
      else if (svcTab === "docker") drawDocker(body, docker);
      else drawPackages(body, pkgs);
    };
    $$("#svcTabs .tab").forEach((b) => {
      b.onclick = () => {
        svcTab = b.dataset.tab;
        $$("#svcTabs .tab").forEach((x) => x.classList.toggle("active", x.dataset.tab === svcTab));
        draw();
      };
    });
    draw();
  }

  function drawListen(root, svc) {
    const web = new Set((svc.web_listeners || []).map((w) => w.local + w.proto));
    const rows = (svc.listening || [])
      .map(
        (l) => `<tr${web.has(l.local + l.proto) ? ' style="background:rgba(99,102,241,.08)"' : ""}>
        <td class="mono"><b>${esc(l.local)}</b></td>
        <td>${esc(l.process || "—")}</td>
        <td class="muted mono small">${esc(l.proto)}</td>
        <td class="muted mono small">${l.pid || ""}</td>
        <td>${web.has(l.local + l.proto) ? '<span class="chip chip-info">WebUI</span>' : ""}</td>
      </tr>`
      )
      .join("");
    root.innerHTML = `<div class="grid g2">
      ${card("监听清单", "ss -lntupH", "", table(
        [{ t: "地址:端口" }, { t: "进程" }, { t: "协议" }, { t: "PID" }, { t: "标记" }], rows))}
      ${card("关键单元", "systemctl is-active", "", table(
        [{ t: "单元" }, { t: "状态" }],
        (svc.key_units || []).map(
          (u) => `<tr><td class="mono">${esc(u.name)}</td>
          <td><span class="st ${u.state === "active" ? "on" : "off"}"></span>${esc(u.state)}</td></tr>`
        )
      ))}
    </div>`;
  }

  function drawUnits(root, svc) {
    const rows = (svc.running || [])
      .map(
        (r) => `<tr><td class="mono">${esc(r.unit)}</td><td>${esc(r.active)}</td>
        <td>${esc(r.sub)}</td><td class="muted small">${esc(r.desc || "")}</td></tr>`
      )
      .join("");
    root.innerHTML = card("运行中的服务", `systemctl list-units --state=running · ${svc.running_count || 0} 个`, "",
      table([{ t: "单元" }, { t: "active" }, { t: "sub" }, { t: "描述" }], rows));
  }

  function drawDocker(root, docker) {
    if (!docker.present) {
      root.innerHTML = card("Docker", "", "", `<div class="empty">未检测到可用的 Docker 守护进程<br><span class="muted small">${esc(docker.reason || "")}</span></div>`);
      return;
    }
    const cRows = (docker.containers || [])
      .map(
        (c) => `<tr>
        <td><span class="st ${c.state === "running" ? "on" : "off"}"></span><b>${esc(c.names)}</b></td>
        <td class="mono small truncate">${esc(c.image)}</td>
        <td class="muted small">${esc(c.status)}</td>
        <td class="mono small">${esc(c.ports || "—")}</td>
        <td>${c.project ? `<span class="chip chip-cat">${esc(c.project)}</span>` : ""}</td>
      </tr>`
      )
      .join("");
    const iRows = (docker.images || [])
      .map(
        (i) => `<tr><td class="mono">${esc(i.repository)}:${esc(i.tag)}</td>
        <td>${esc(i.size)}</td><td class="muted small">${esc(i.created)}</td></tr>`
      )
      .join("");
    const pRows = (docker.projects || [])
      .map(
        (p) => `<tr><td><b>${esc(p.name)}</b></td><td class="mono small">${esc(p.workdir)}</td>
        <td>${p.running}/${p.count} 运行</td></tr>`
      )
      .join("");
    root.innerHTML = `<div class="section"><div class="grid g2">
      ${card("容器", `${docker.containers.length} 个 · 运行 ${docker.running || 0} · Docker ${esc(docker.version)}`, "",
        table([{ t: "名称" }, { t: "镜像" }, { t: "状态" }, { t: "端口" }, { t: "Compose" }], cRows))}
      <div class="grid" style="gap:14px">
        ${card("Compose 项目", "按标签识别", "", table([{ t: "项目" }, { t: "目录" }, { t: "容器" }], pRows))}
        ${card("镜像", "", "", table([{ t: "镜像" }, { t: "大小" }, { t: "构建" }], iRows))}
      </div>
    </div></div>`;
  }

  function drawPackages(root, pkgs) {
    root.innerHTML = card("已安装软件包", `dpkg-query · ${pkgs.total} 个（输入关键字过滤）`,
      `<input id="pkgQ" placeholder="搜索：nginx / docker / panel…" style="background:rgba(7,11,20,.75);border:1px solid var(--line-strong);color:var(--txt);border-radius:10px;padding:7px 12px;font-size:13px;width:220px;outline:none">`,
      `<div id="pkgList" style="max-height:520px;overflow:auto"></div>`);
    const render = (q) => {
      q = (q || "").toLowerCase();
      const items = (pkgs.items || [])
        .filter((p) => !q || p.name.toLowerCase().includes(q))
        .slice(0, 500);
      const rows = items
        .map((p) => `<tr><td class="mono">${esc(p.name)}</td><td class="mono muted small">${esc(p.version)}</td></tr>`)
        .join("");
      $("#pkgList").innerHTML = table([{ t: "包" }, { t: "版本" }], rows) + (items.length >= 500 ? `<div class="empty">仅显示前 500 条，请细化关键字</div>` : "");
    };
    render("");
    $("#pkgQ").oninput = (e) => render(e.target.value);
  }

  // ================= 审计 · 备份 =================
  async function renderAudit(view) {
    const d = await get("/api/audit?limit=200");
    const statusChip = (s) => {
      const m = { applied: "chip-ok", rolled_back: "chip-warn", failed: "chip-bad", partial: "chip-warn" };
      const t = { applied: "已应用", rolled_back: "已回滚", failed: "失败", partial: "部分" };
      return `<span class="chip ${m[s] || ""}">${t[s] || esc(s)}</span>`;
    };
    const rows = (d.entries || [])
      .map(
        (e) => `<tr>
        <td class="mono small">${esc(e.ts || "")}</td>
        <td class="mono small">${esc(e.op || "")}</td>
        <td>${esc(e.title || "")}<div class="muted small">${esc((e.commands || []).slice(0, 2).join(" ; "))}</div></td>
        <td><span class="risk risk-${esc(e.risk || "low")}">${RD.riskText(e.risk || "low")}</span></td>
        <td>${statusChip(e.status)}</td>
        <td class="muted small">${esc(e.mode || "")}</td>
      </tr>`
      )
      .join("");

    const bRows = (d.backups || [])
      .map(
        (b) => `<tr>
        <td class="mono small">${esc(b.ts)}</td>
        <td class="mono">${esc(b.path)}</td>
        <td class="right">${fmtBytes(b.size)}</td>
        <td class="muted small">${esc(b.reason || "")}</td>
        <td class="right"><button class="btn btn-sm" data-restore="${esc(b.id)}">还原</button></td>
      </tr>`
      )
      .join("");

    view.innerHTML = `
      <div class="section">
        <div class="row"><span class="chip">变更记录 ${d.entries.length}</span><span class="chip">文件备份 ${d.backups.length}</span>
        <span class="spacer"></span><span class="muted small">每次变更自动记录；备份保留最近 500 份</span></div>
      </div>
      <div class="section">
        ${card("变更审计", "audit.jsonl · 最新在前", "", table(
          [{ t: "时间" }, { t: "操作" }, { t: "详情" }, { t: "风险" }, { t: "结果" }, { t: "模式" }],
          rows || [{ toString: () => '<tr><td colspan="6"><div class="empty">尚无变更记录</div></td></tr>' }]
        ))}
      </div>
      <div class="section">
        ${card("文件备份", "写入前自动快照", "", table(
          [{ t: "时间" }, { t: "路径" }, { cls: "right", t: "大小" }, { t: "原因" }, { cls: "right", t: "" }],
          bRows
        ))}
      </div>`;

    $$("#view button[data-restore]").forEach((b) => {
      b.onclick = async () => {
        if (!confirm("将该文件还原到此备份的内容？")) return;
        await confirmPlan("file.restore", { backup_id: b.dataset.restore }, { onDone: refresh });
      };
    });
  }

  // ================= 检测报告 =================
  async function renderDetection(view) {
    const d = await get("/api/detection");
    const fresh = d.fresh || {};
    const saved = d.saved;
    const b = fresh.backends || {};

    const row = (name, obj) => {
      const ok = obj.present;
      const extra = obj.running !== undefined ? (obj.running ? "运行中" : "未运行") : obj.version || "";
      return `<tr>
        <td><b>${esc(name)}</b></td>
        <td><span class="st ${ok ? "on" : "off"}"></span>${ok ? "检测到" : "无"}</td>
        <td class="muted small">${esc(extra)}</td>
        <td class="mono muted small">${esc(obj.rules !== undefined ? obj.rules + " 条规则" : "")}</td>
      </tr>`;
    };

    const rows = [
      ["iproute2 (ip)", b.iproute2 || {}],
      ["NetworkManager", b.network_manager || {}],
      ["systemd-networkd", b.networkd || {}],
      ["ifupdown (/etc/network)", b.ifupdown || {}],
      ["nftables", b.nftables || {}],
      ["iptables", b.iptables || {}],
      ["dnsmasq", b.dnsmasq || {}],
      ["Kea DHCP", b.kea || {}],
      ["ISC dhcpd", b.isc_dhcp || {}],
      ["Docker", b.docker || {}],
      ["hostapd", b.hostapd || {}],
      ["pppd", b.pppd || {}],
    ]
      .map(([n, o]) => row(n, o))
      .join("");

    view.innerHTML = `
      <div class="section">
        <div class="card" style="border-color:rgba(52,211,153,.3);background:rgba(52,211,153,.05)">
          <div class="card-t" style="color:#34d399">✓ 非侵入检测</div>
          <div class="small" style="margin-top:6px;color:var(--txt-2)">${esc(fresh.promise || "")}</div>
          <div class="small muted" style="margin-top:4px">检测时间 ${esc(fresh.ts || "")} · 内核 ${esc(fresh.kernel || "")} · 模式 ${esc(fresh.mode || "")}</div>
        </div>
      </div>
      <div class="section">
        <div class="grid g2">
          ${card("本次检测（实时）", "routedeck detect", "", table(
            [{ t: "组件" }, { t: "状态" }, { t: "详情" }, { t: "附加" }], rows))}
          ${card("安装期快照", saved ? "首次运行保存于 data-dir/detection.json" : "尚无快照", "", saved ? `
            <div class="kv">${Object.entries((saved.backends || {}))
              .map(([k, v]) => `<span class="k">${esc(k)}</span><span class="v">${v.present ? "✓" : "—"} ${esc(v.version || (v.rules !== undefined ? v.rules + " rules" : ""))}</span>`)
              .join("")}</div>` : '<div class="empty">未找到快照</div>')}
        </div>
      </div>`;
  }

  // ================= 系统 · 任务 =================
  async function renderSystem(view) {
    const d = await get("/api/system");

    const rows = (d.tasks || [])
      .map(
        (t) => `<tr>
        <td><b>${esc(t.name)}</b>
          <span class="chip ${t.kind === "reboot" ? "chip-warn" : "chip-info"}">${t.kind === "reboot" ? "定时重启" : "定时命令"}</span></td>
        <td class="mono small">${esc(t.on_calendar)}</td>
        <td class="mono small truncate" title="${esc(t.exec)}">${esc(t.exec)}</td>
        <td class="mono small muted">${esc(t.next || "—")}</td>
        <td><span class="st ${t.enabled === "enabled" ? "on" : "off"}"></span>${esc(t.enabled)}</td>
        <td><span class="st ${t.active === "active" ? "on" : "off"}"></span>${esc(t.active)}</td>
        <td class="right"><button class="btn btn-sm btn-danger" data-deltask="${esc(t.name)}">删除</button></td>
      </tr>`
      )
      .join("");

    view.innerHTML = `
      <div class="section">
        <div class="grid g2">
          <div class="card" style="border-color:rgba(248,113,113,.35);background:rgba(248,113,113,.05)">
            <div class="card-t" style="color:#f87171">⚠ 立即重启路由器</div>
            <div class="small muted" style="margin:8px 0 14px">执行 <span class="mono">systemctl reboot</span>。重启期间 WebUI / SSH / 全部网络中断，约 1 分钟后恢复——请确认设备重启后能自动联网。</div>
            <button class="btn btn-danger" id="btnReboot">立即重启…</button>
          </div>
          <div class="card">
            <div class="card-t">定时任务如何工作</div>
            <div class="small muted" style="margin-top:8px">
              每个任务写入两个 systemd 单元（<span class="mono">/etc/systemd/system/routedeck-task-&lt;名&gt;.service/.timer</span>），
              走和其它操作一样的 Plan → 确认 → Apply 管线：写入前自动备份，删除可回滚。
              到点由 systemd 触发，不依赖 WebUI 是否在线。
            </div>
            <div class="kv" style="margin-top:10px">
              <span class="k">单元目录</span><span class="v mono">${esc(d.unit_dir || "/etc/systemd/system")}</span>
              <span class="k">任务数</span><span class="v">${(d.tasks || []).length}</span>
            </div>
          </div>
        </div>
      </div>
      <div class="section">
        ${card("定时任务", `systemctl list-timers · routedeck-task-*`,
          `<button class="btn btn-primary" id="btnAddTask">＋ 新建定时任务</button>`,
          table(
            [{ t: "任务" }, { t: "OnCalendar" }, { t: "执行命令" }, { t: "下次运行" }, { t: "启用" }, { t: "活动" }, { cls: "right", t: "" }],
            rows
          ))}
      </div>`;

    $("#btnReboot").onclick = async () => {
      await confirmPlan("sys.reboot", {}, { applyLabel: "确认重启路由器", onDone: () => RD.toast("重启指令已下发，设备即将断开", "ok") });
    };

    $("#btnAddTask").onclick = () => {
      modal(`
        ${modalHead("新建定时任务")}
        <div class="m-body"><div class="form">
          <div class="f-grid2">
            <div class="f-row"><label>任务名（字母数字 _ -）</label><input id="tkName" placeholder="daily-reboot"></div>
            <div class="f-row"><label>类型</label>
              <select id="tkKind">
                <option value="reboot">定时重启</option>
                <option value="command">定时命令</option>
              </select></div>
          </div>
          <div class="f-row"><label>OnCalendar（systemd 时间表达式）</label>
            <input id="tkCal" placeholder="*-*-* 03:30:00" value="*-*-* 03:30:00">
            <datalist id="tkCalList">
              <option value="*-*-* 03:30:00">每天 03:30</option>
              <option value="Mon *-*-* 04:00:00">每周一 04:00</option>
              <option value="*-*-* 02/6:00:00">每 6 小时</option>
            </datalist>
          </div>
          <div class="f-row" id="tkCmdRow" style="display:none">
            <label>执行命令（绝对路径，systemd 不经 shell）</label>
            <input id="tkCmd" placeholder="/usr/bin/journalctl --vacuum-time=14d">
          </div>
          <div class="warn-item"><span>ⓘ</span><span>生成计划时会用 <span class="mono">systemd-analyze calendar</span> 校验时间表达式；执行时写入单元文件并 <span class="mono">enable --now</span>。</span></div>
        </div></div>
        <div class="m-foot">
          <button class="btn btn-ghost" onclick="RD.closeModal()">取消</button>
          <button class="btn btn-primary" id="tkNext">生成变更计划</button>
        </div>`);
      const kindSel = $("#tkKind");
      const syncKind = () => {
        $("#tkCmdRow").style.display = kindSel.value === "command" ? "" : "none";
        $("#tkCal").list = kindSel.value === "reboot" ? "tkCalList" : null;
      };
      kindSel.onchange = syncKind;
      syncKind();
      $("#tkNext").onclick = async () => {
        const params = {
          name: $("#tkName").value.trim(),
          kind: $("#tkKind").value,
          on_calendar: $("#tkCal").value.trim(),
        };
        if (params.kind === "command") params.command = $("#tkCmd").value.trim();
        closeModal();
        await confirmPlan("sys.add_timer", params, { onDone: refresh });
      };
    };

    $$("#view button[data-deltask]").forEach((b) => {
      b.onclick = async () => {
        if (!confirm("删除定时任务 " + b.dataset.deltask + "？（单元文件先备份，可回滚）")) return;
        await confirmPlan("sys.del_timer", { name: b.dataset.deltask }, { onDone: refresh });
      };
    });
  }

  // ---------- register ----------
  RD.registerRoute("overview", { render: renderOverview, interval: 3000 });
  RD.registerRoute("interfaces", { render: renderInterfaces, interval: 15000 });
  RD.registerRoute("routes", { render: renderRoutes });
  RD.registerRoute("nat", { render: renderNat });
  RD.registerRoute("dhcp", { render: renderDhcp });
  RD.registerRoute("services", { render: renderServices });
  RD.registerRoute("audit", { render: renderAudit });
  RD.registerRoute("detection", { render: renderDetection });
  RD.registerRoute("system", { render: renderSystem });
})();
