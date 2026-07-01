#!/bin/bash
# Sentinel - Linux Agent 一键诊断
set -euo pipefail

MANAGER="${1:-}"
CONF="/var/ossec/etc/ossec.conf"
LOG="/var/ossec/logs/ossec.log"

echo "==== Sentinel · Linux Agent 诊断 ===="
echo "[系统] $(uname -a)"
echo "[服务]"
systemctl status wazuh-agent --no-pager 2>/dev/null || true

if [ -f "$CONF" ]; then
  DETECTED="$(sed -n 's#.*<address>\([^<]*\)</address>.*#\1#p' "$CONF" | head -1)"
  MANAGER="${MANAGER:-$DETECTED}"
  echo "[Manager] ${MANAGER:-未配置}"
else
  echo "[配置] 未找到 $CONF"
fi

if [ -n "$MANAGER" ]; then
  echo "[端口连通]"
  for port in 1514 1515; do
    if command -v nc >/dev/null 2>&1; then
      nc -z -w 3 "$MANAGER" "$port" && echo "  $port OK" || echo "  $port FAIL"
    else
      echo "  缺少 nc，跳过 $port"
    fi
  done
fi

echo "[最近日志]"
if [ -f "$LOG" ]; then
  tail -80 "$LOG"
else
  echo "未找到 $LOG"
fi
