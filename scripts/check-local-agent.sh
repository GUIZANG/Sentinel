#!/bin/bash
# GuiZang 本机 Wazuh Agent 自检脚本。
# 用法：./check-local-agent.sh [服务器IP或域名]
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OS="$(uname -s)"
SERVER="${1:-}"
OSSEC_DIR="/var/ossec"
if [ "$OS" = "Darwin" ]; then
  OSSEC_DIR="/Library/Ossec"
fi

ok() { echo "  [OK] $*"; }
warn() { echo "  [!] $*"; }
bad() { echo "  [X]  $*"; }

detect_agent_name() {
  local name=""
  if [ "$OS" = "Darwin" ]; then
    name="$(scutil --get LocalHostName 2>/dev/null || true)"
  fi
  [ -z "$name" ] && name="$(hostname -s 2>/dev/null || hostname 2>/dev/null || true)"
  echo "$name"
}

read_manager_from_config() {
  local conf="$OSSEC_DIR/etc/ossec.conf"
  [ -r "$conf" ] || conf="$OSSEC_DIR/etc/ossec.conf"
  if [ -r "$conf" ]; then
    awk '
      /<server>/ { in_server=1 }
      in_server && /<address>/ {
        gsub(/.*<address>|<\/address>.*/, "", $0);
        print $0;
        exit
      }
      /<\/server>/ { in_server=0 }
    ' "$conf" 2>/dev/null || true
  fi
}

check_agent_running() {
  if [ ! -d "$OSSEC_DIR" ]; then
    bad "未找到 Wazuh Agent 目录：$OSSEC_DIR"
    return 1
  fi
  if "$OSSEC_DIR/bin/wazuh-control" status 2>/dev/null | awk 'tolower($0) ~ /running|is running/ { found=1 } END { exit found ? 0 : 1 }'; then
    ok "Wazuh Agent 正在运行"
  else
    bad "Wazuh Agent 未运行，可尝试：sudo $OSSEC_DIR/bin/wazuh-control start"
  fi
}

check_port() {
  local host="$1" port="$2"
  if command -v nc >/dev/null 2>&1; then
    if nc -vz -w 3 "$host" "$port" >/dev/null 2>&1; then
      ok "$host:$port 可连通"
    else
      bad "$host:$port 不通，请检查服务器、防火墙或安全组"
    fi
  else
    warn "未找到 nc，跳过 $host:$port 连通性检查"
  fi
}

load_server_env() {
  local env_file="$ROOT_DIR/server/.env"
  if [ -f "$env_file" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$env_file"
    set +a
  fi
}

check_registration() {
  local host="$1" agent_name="$2"
  local api_user="${WAZUH_API_USER:-wazuh-wui}"
  local api_pass="${WAZUH_API_PASSWORD:-MyS3cr37P450r.*-}"
  local api="https://${host}:55000"
  if ! command -v curl >/dev/null 2>&1; then
    warn "未找到 curl，跳过 Wazuh 注册状态检查"
    return 0
  fi
  local token
  token="$(curl -k -fsS -u "${api_user}:${api_pass}" -X POST "${api}/security/user/authenticate" 2>/dev/null | awk -F'"' '/token/ {print $4; exit}' || true)"
  if [ -z "$token" ]; then
    warn "无法登录 Wazuh API，跳过注册状态检查（如在客户端运行，可忽略）"
    return 0
  fi
  local agents
  agents="$(curl -k -fsS -H "Authorization: Bearer ${token}" "${api}/agents?select=id,name,status,lastKeepAlive,ip&limit=500" 2>/dev/null || true)"
  if echo "$agents" | tr '\n' ' ' | grep -q "\"name\":\"${agent_name}\""; then
    local last
    last="$(echo "$agents" | tr '\n' ' ' | sed -n "s/.*\"name\":\"${agent_name}\"[^}]*\"lastKeepAlive\":\"\([^\"]*\)\".*/\1/p")"
    ok "Wazuh 已注册该 Agent：${agent_name}"
    [ -n "$last" ] && ok "最近心跳时间：$last"
  else
    bad "Wazuh 未找到 Agent：${agent_name}"
  fi
}

echo "==== GuiZang · 本机 Agent 自检 ===="
AGENT_NAME="$(detect_agent_name)"
CONFIG_MANAGER="$(read_manager_from_config)"
SERVER="${SERVER:-$CONFIG_MANAGER}"
echo "  本机 Agent 名：${AGENT_NAME:-未知}"
echo "  配置的 Manager：${CONFIG_MANAGER:-未读取到}"
echo "  检查目标服务器：${SERVER:-未指定}"

check_agent_running || true
if [ -z "${SERVER:-}" ]; then
  bad "未指定服务器，也未从 Agent 配置读取到 Manager 地址"
  exit 1
fi
if [ -n "$CONFIG_MANAGER" ] && [ "$CONFIG_MANAGER" = "$SERVER" ]; then
  ok "Manager 地址与检查目标一致"
elif [ -n "$CONFIG_MANAGER" ]; then
  warn "Manager 地址不一致：配置为 $CONFIG_MANAGER，当前检查 $SERVER"
fi

check_port "$SERVER" 1514
check_port "$SERVER" 1515
load_server_env
check_registration "$SERVER" "$AGENT_NAME"
echo "==== 自检完成 ===="
