# RouteDeck

**在已有 Debian 路由器上"渲染"一个 WebUI —— 不重装系统、不破坏现有配置。**

RouteDeck 面向已经跑着 Debian（13 trixie 等）+ NetworkManager/nftables/dnsmasq 的主路由机器：
安装 = 拷一个静态二进制 + 注册 systemd 单元；首次运行只做**只读识别**；
所有变更都走 **Plan → 确认 → Apply → Rollback** 管线，由你在 WebUI 里逐条确认后才执行。

> 设计参考 [KPanel](https://github.com/kejilion/KPanel) 的面板形态，但不采用
> [landscape](https://github.com/ThisSeanZhang/landscape) 式的"重装系统"思路 —— 非侵入是硬约束。

## 原则

1. **安装与检测不改配置** — `install.sh` 只写 `/opt/routedeck`、`/var/lib/routedeck`、
   一个 systemd 单元；`detect` 子命令只读。
2. **变更仅经 WebUI 确认后执行** — 每个写操作先生成计划（含将执行的命令、风险等级、
   警告、回滚步骤），确认后才 apply。
3. **每个计划自带幂等回滚** — 文件写入前 sha256 校验 + 备份；命令按撤销顺序回滚；
   全部动作记录在 `audit.jsonl`。

## 功能（v0.1）

| 域 | 内容 |
|---|---|
| 总览 | CPU/内存/流量、健康度、接口速览、**访问入口（LAN 地址优先展示）**、已识别 WebUI 项目 |
| 接口 | 实时检测网卡（enp1s0/ens1p0…，**不硬编码**）、NM 连接配置 IP、启用/停用、MTU/克隆 MAC、**创建以太网（LAN 口/DHCP WAN）**、**换绑网卡（WAN/LAN 角色互换）** |
| PPPoE | 创建/编辑拨号（账号/密码/ISP 服务名/ppp.mtu）、断线重拨 |
| 双 WAN | route-metric 出口优先级、never-default |
| 路由 | 内核路由表/策略规则只读、添加/删除静态路由 |
| NAT/防火墙 | 托管端口转发（DNAT）、追加放行、MASQUERADE 按出口开关、DMZ |
| DHCP/DNS | 作用域+下发选项、静态绑定、本地域名解析、上游 DNS；NM ICS/其它 dhcp-range 冲突检测（ICS 在管 → 硬拒绝） |
| 服务/软件 | **软件入口（识别青龙/Grafana 等已装软件，一键打开 WebUI）**、监听端口、systemd、Docker 容器/Compose 项目、dpkg 软件 |
| 系统/任务 | **在线升级**（GitHub 检查版本 → 下载 → ELF/版本校验 → 原子替换 → 自动重启，旧版可回滚）、**立即重启**、**systemd 定时任务**（定时重启/定时命令，OnCalendar 校验，写入前备份、可回滚） |
| 审计 | 变更历史、文件备份、一键还原 |

托管写入均带 `rd:` 标记，只增删自己的对象：
- nftables → `table inet routedeck`（prerouting DNAT / postrouting masquerade，规则注释 `rd:<id>`）
- dnsmasq → `/etc/dnsmasq.d/routedeck.conf`（"Managed by RouteDeck" 标记片段）

## 安装（Debian 路由器）

**方式 A：克隆仓库一键安装（推荐测试）**

```bash
git clone https://github.com/EmersonLopez2005/routedeck.git
cd routedeck/dist/routedeck-v0.1.0-linux-x64
sudo ./install.sh
```

**方式 B：release zip**

```bash
# 从 release zip 解压后
sudo ./install.sh                 # 默认端口 8080
sudo RD_PORT=9090 ./install.sh    # 自定义端口
```

安装完成后会直接打印 **LAN 口访问入口**（`http://<LAN IP>:8080/`），面板总览页也有「访问入口」条。

> 截图（mock 模式）：[总览页](dist/ui-overview.png) · [接口页](dist/ui-interfaces.png) · [DHCP](dist/ui-dhcp.png) · [NAT](dist/ui-nat.png) · [服务·软件入口](dist/ui-services.png) · [系统·任务](dist/ui-system.png) · [系统·在线升级](dist/ui-system-upgrade.png)

```bash
journalctl -u routedeck -f        # 日志
sudo ./uninstall.sh               # 卸载（保留数据）
sudo ./uninstall.sh --purge       # 卸载并清除审计/备份
```

## CLI

```bash
routedeck serve   [--bind] [--port] [--data-dir] [--mock] [--token]
routedeck detect  [--data-dir] [--json]   # 只读检测，打印/保存快照
routedeck version
```

## 架构

```
web/static (原生 JS SPA, include_dir 嵌入二进制)
   │  REST: /api/{overview,interfaces,routes,nat,dhcp,services,docker,packages,audit,detection}
   ▼
src/api.rs (axum)  ── Plan/Apply/Rollback ──► src/backend/{mod,ops}.rs
   ▲                                              │ 只在 apply 时执行
src/discovery (全只读)                            ▼
   ip -j / nmcli -t / nft -j / ss / docker / dpkg-query / systemd   ← 只读识别
```

- `Mode::Live` / `Mode::Mock`：mock 下 apply 不真执行命令，供 UI 联调。
- 计划对象含 `commands`（将执行的 argv）、`files`（完整文件内容 + expect_sha + 备份）、
  `rollback`（撤销步骤，幂等）、`warnings`、`risk`、`may_disconnect`。

## License

MIT
