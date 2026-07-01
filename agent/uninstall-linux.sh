#!/bin/bash
# Sentinel - Linux Agent 卸载脚本
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要管理员权限，请用 sudo 重新运行：sudo bash $0"
  exit 1
fi

echo "==== Sentinel · Linux Agent 卸载 ===="
systemctl stop wazuh-agent 2>/dev/null || true
systemctl disable wazuh-agent 2>/dev/null || true

if command -v apt-get >/dev/null 2>&1; then
  apt-get remove -y wazuh-agent || true
elif command -v dnf >/dev/null 2>&1; then
  dnf remove -y wazuh-agent || true
elif command -v yum >/dev/null 2>&1; then
  yum remove -y wazuh-agent || true
elif command -v zypper >/dev/null 2>&1; then
  zypper -n remove wazuh-agent || true
else
  echo "[!] 未识别包管理器，请手动卸载 wazuh-agent。"
fi

rm -f /var/ossec/etc/shared/guizang-firewall.sh /var/ossec/etc/guizang-agent-note.txt 2>/dev/null || true
echo "[OK] 卸载完成。如需清空历史配置，可手动删除 /var/ossec。"
