#!/usr/bin/env bash
# RouteDeck installer — 只拷文件 + 注册 systemd 单元，不改任何网络配置。
# 安装完成后首次访问 WebUI 时才会执行只读检测；所有变更均需在 UI 中确认。
set -euo pipefail

BIN_SRC="$(cd "$(dirname "$0")" && pwd)/routedeck"
UNIT_SRC="$(cd "$(dirname "$0")" && pwd)/routedeck.service"

INSTALL_DIR=/opt/routedeck
DATA_DIR=/var/lib/routedeck
UNIT=/etc/systemd/system/routedeck.service
PORT="${RD_PORT:-8080}"
BIND="${RD_BIND:-0.0.0.0}"

if [[ $EUID -ne 0 ]]; then
  echo "请以 root 运行: sudo $0" >&2
  exit 1
fi

if [[ ! -f "$BIN_SRC" ]]; then
  echo "未找到 $BIN_SRC — 请确认与本脚本同目录存在 routedeck 二进制" >&2
  exit 1
fi

# ---- 架构检查（避免在不匹配的机器上装了跑不起来）----
want_arch="x86_64"
have_arch="$(uname -m)"
if [[ "$have_arch" != "$want_arch" && "$have_arch" != "amd64" ]]; then
  echo "警告: 当前架构 $have_arch，二进制为 $want_arch（musl 静态）。继续安装可能无法运行。" >&2
fi

echo "==> 安装二进制到 $INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$DATA_DIR"
install -m 0755 "$BIN_SRC" "$INSTALL_DIR/routedeck"

echo "==> 安装 systemd 单元 $UNIT"
sed -e "s|--port 8080|--port ${PORT}|" \
    -e "s|--bind 0.0.0.0|--bind ${BIND}|" \
    "$UNIT_SRC" > "$UNIT"
chmod 0644 "$UNIT"

echo "==> 首次只读检测（不修改任何配置）"
"$INSTALL_DIR/routedeck" detect --data-dir "$DATA_DIR" || true

systemctl daemon-reload
systemctl enable routedeck >/dev/null 2>&1 || true
systemctl restart routedeck

echo
echo "==> RouteDeck 已安装"
echo "    URL:      http://<本机IP>:${PORT}/"
echo "    数据/备份: ${DATA_DIR}   （审计 audit.jsonl、文件备份）"
echo "    查看日志: journalctl -u routedeck -f"
echo "    卸载:     sudo ./uninstall.sh"
echo
echo "原则: 安装与检测不改配置；变更仅经 WebUI 确认后执行。"
