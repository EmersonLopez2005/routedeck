#!/usr/bin/env bash
# RouteDeck uninstall — 停服务、删单元、删二进制；数据与备份默认保留。
# 用 --purge 同时删除 /var/lib/routedeck（含审计与文件备份）。
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "请以 root 运行: sudo $0 [--purge]" >&2
  exit 1
fi

echo "==> 停止并禁用 routedeck 服务"
systemctl disable --now routedeck 2>/dev/null || true

echo "==> 删除 systemd 单元"
rm -f /etc/systemd/system/routedeck.service
systemctl daemon-reload

echo "==> 删除二进制"
rm -rf /opt/routedeck

if [[ "${1:-}" == "--purge" ]]; then
  echo "==> 清除数据目录 /var/lib/routedeck（审计与备份将丢失）"
  rm -rf /var/lib/routedeck
else
  echo "    数据保留于 /var/lib/routedeck（如需清除: sudo $0 --purge）"
fi

echo "==> RouteDeck 已卸载。它未修改你的网络配置，无需恢复操作。"
