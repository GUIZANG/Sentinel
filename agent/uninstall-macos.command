#!/bin/bash
# Sentinel - macOS Agent 卸载脚本
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  exec sudo /bin/bash "$0" "$@"
fi

echo "==== Sentinel · macOS Agent 卸载 ===="
/Library/Ossec/bin/wazuh-control stop 2>/dev/null || true
launchctl bootout system /Library/LaunchDaemons/com.wazuh.agent.plist 2>/dev/null || true
launchctl remove com.wazuh.agent 2>/dev/null || true

if command -v pkgutil >/dev/null 2>&1; then
  for pkg in $(pkgutil --pkgs | grep -Ei 'wazuh|ossec' || true); do
    pkgutil --forget "$pkg" >/dev/null 2>&1 || true
  done
fi

rm -rf /Library/Ossec /Library/LaunchDaemons/com.wazuh.agent.plist 2>/dev/null || true
echo "[OK] 卸载完成。"
