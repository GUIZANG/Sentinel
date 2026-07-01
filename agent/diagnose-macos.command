#!/bin/bash
# Sentinel - macOS Agent 一键诊断
set -euo pipefail

MANAGER="${1:-}"
CONF="/Library/Ossec/etc/ossec.conf"
LOG="/Library/Ossec/logs/ossec.log"

echo "==== Sentinel · macOS Agent 诊断 ===="
echo "[系统] $(sw_vers -productName) $(sw_vers -productVersion) $(uname -m)"
echo "[服务]"
/Library/Ossec/bin/wazuh-control status 2>/dev/null || echo "Wazuh 控制命令不可用"

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
    nc -z -G 3 "$MANAGER" "$port" >/dev/null 2>&1 && echo "  $port OK" || echo "  $port FAIL"
  done
fi

echo "[最近日志]"
if [ -f "$LOG" ]; then
  tail -80 "$LOG"
else
  echo "未找到 $LOG"
fi
