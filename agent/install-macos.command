#!/bin/bash
# GuiZang - macOS 安全监控终端一键安装脚本
# 用法：
#   方式一（推荐）：先在下方【每客户改一次】填好服务器IP，然后零输入运行：
#         sudo ./install-macos.command
#   方式二：临时指定： sudo ./install-macos.command 192.168.1.10
# 双击运行时会自动用 osascript 申请管理员权限并自动发现服务器。
set -euo pipefail

# ============================================================
#  【每客户改一次】把这里填成该客户服务器(Manager)的固定 IP，
#   之后所有 Mac 装机零输入。建议给服务器设静态 IP 或用域名。
DEFAULT_MANAGER=""        # 例：DEFAULT_MANAGER="192.168.1.10"
DEFAULT_REG_PASSWORD=""   # 一般留空：启用了注册密码时，运行时会提示你手动输入（不写进脚本更安全）
DEFAULT_VERSION=""        # 由 deploy.sh 自动填入服务器(Manager)版本以保持一致；留空=自动取最新
DEFAULT_AGENT_NOTE=""     # 可选备注，仅安装时展示并写入本机备注文件，不影响 Wazuh 注册名
# ============================================================

# 版本优先级：环境变量 WAZUH_VERSION > 脚本内默认(对齐 Manager) > 自动获取最新 > 回退。
FALLBACK_VERSION="4.14.5"
resolve_latest() {
  local tag
  tag="$(curl -fsSL --max-time 8 https://api.github.com/repos/wazuh/wazuh/releases/latest 2>/dev/null \
        | sed -n 's/.*"tag_name"[ ]*:[ ]*"v\{0,1\}\([0-9.]*\)".*/\1/p' | head -1)"
  echo "${tag:-$FALLBACK_VERSION}"
}

download_file() {
  local url="$1"
  local out="$2"
  local i
  for i in 1 2 3 4 5; do
    if curl -fL --connect-timeout 15 --retry 3 --retry-delay 2 -o "$out" "$url"; then
      [ -s "$out" ] && return 0
    fi
    echo "    下载失败，${i}/5，3 秒后重试 ..."
    sleep 3
  done
  echo "[X] 下载失败：$url"
  return 1
}

WAZUH_VERSION="${WAZUH_VERSION:-${DEFAULT_VERSION:-$(resolve_latest)}}"
MANAGER="${1:-}"
# 优先使用 macOS LocalHostName（ASCII、稳定），避免中文 ComputerName 被过滤后变成错名。
AGENT_NAME="${2:-$(scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || scutil --get ComputerName 2>/dev/null || hostname)}"
REG_PASSWORD="${3:-$DEFAULT_REG_PASSWORD}"
AGENT_NOTE="${4:-${AGENT_NOTE:-$DEFAULT_AGENT_NOTE}}"

# Wazuh 代理名只允许字母数字和 - _ . ；空格转 -，去掉中文等非法字符（否则注册被拒）
AGENT_NAME="$(printf '%s' "$AGENT_NAME" | tr ' ' '-' | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
[ -z "$AGENT_NAME" ] && AGENT_NAME="$(hostname -s 2>/dev/null | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
[ -z "$AGENT_NAME" ] && AGENT_NAME="macos-agent"

# 自动发现服务器：扫描本网段 1514 端口（通信端口）
find_manager() {
  local ip prefix host
  ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
  [ -z "$ip" ] && return 0
  prefix="$(echo "$ip" | cut -d. -f1-3)"
  echo "[*] 未指定服务器地址，正在本网段 ${prefix}.0/24 搜索 GuiZang 服务器(端口1514) ..." >&2
  for h in $(seq 1 254); do
    ( nc -z -G 1 -w 1 "${prefix}.${h}" 1514 >/dev/null 2>&1 && echo "${prefix}.${h}" ) &
  done > /tmp/.wazuh_scan 2>/dev/null
  wait
  host="$(grep -v "^${ip}$" /tmp/.wazuh_scan 2>/dev/null | head -1 || true)"
  rm -f /tmp/.wazuh_scan
  [ -n "$host" ] && echo "[*] 发现服务器：$host" >&2
  echo "$host"
}

# 解析 Manager：参数 > 脚本内默认 > 自动发现 > 交互输入
[ -z "$MANAGER" ] && MANAGER="$DEFAULT_MANAGER"
[ -z "$MANAGER" ] && MANAGER="$(find_manager)"
if [ -z "$MANAGER" ]; then
  read -r -p "请输入 GuiZang 服务器的 IP/域名: " MANAGER
fi
if [ -z "$MANAGER" ]; then
  echo "[X] 未确定 Manager 地址，退出。"; exit 1
fi

# 注册密码：参数 > 脚本内默认 > 交互输入。
# 若服务器【启用了注册密码】，请在下面提示处粘贴管理员私下给你的密码后回车；
# 没启用密码就直接回车跳过即可。
if [ -z "$REG_PASSWORD" ]; then
  read -r -p "请输入【服务器注册密码】（没设密码就直接回车跳过）: " REG_PASSWORD || true
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "需要管理员权限，正在申请 ..."
  exec sudo "$0" "$MANAGER" "$AGENT_NAME" "$REG_PASSWORD" "$AGENT_NOTE"
fi

echo "==== GuiZang · macOS 安全监控终端 安装 ===="
echo "服务器    : $MANAGER"
echo "将注册为  : $AGENT_NAME"
[ -n "$AGENT_NOTE" ] && echo "备注      : $AGENT_NOTE"
echo "Version   : $WAZUH_VERSION"
echo

# 兜底：直接改 ossec.conf 里的 manager 地址，确保万无一失
CONF="/Library/Ossec/etc/ossec.conf"
INSTALLED_VERSION="$(pkgutil --pkg-info com.wazuh.pkg.wazuh-agent 2>/dev/null | awk '/^version:/ {print $2}' | sed 's/-.*//' || true)"

if [ -d "/Library/Ossec" ] && [ "${INSTALLED_VERSION}" = "${WAZUH_VERSION}" ]; then
  echo "[1/5] 已安装 Wazuh Agent ${INSTALLED_VERSION}，跳过 pkg 升级。"
else
  # 架构判断（Apple Silicon / Intel 都用 universal 包）
  PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VERSION}-1.intel64.pkg"
  if [ "$(uname -m)" = "arm64" ]; then
    PKG_URL="https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VERSION}-1.arm64.pkg"
  fi
  PKG="/tmp/wazuh-agent-${WAZUH_VERSION}.pkg"

  echo "[1/5] 下载安装包 ..."
  download_file "$PKG_URL" "$PKG"

  echo "[2/5] 预置 Manager 配置 ..."
  # 官方 pkg 支持安装前通过环境变量预置 manager
  echo "WAZUH_MANAGER='${MANAGER}'" > /tmp/wazuh_envs
  echo "WAZUH_AGENT_NAME='${AGENT_NAME}'" >> /tmp/wazuh_envs
  [ -n "$REG_PASSWORD" ] && echo "WAZUH_REGISTRATION_PASSWORD='${REG_PASSWORD}'" >> /tmp/wazuh_envs

  echo "[3/5] 安装 Agent ..."
  /Library/Ossec/bin/wazuh-control stop >/dev/null 2>&1 || true
  installer -pkg "$PKG" -target /
fi

if [ -f "$CONF" ]; then
  /usr/bin/sed -i '' -E "s#<address>[^<]*</address>#<address>${MANAGER}</address>#" "$CONF" || true
fi

# 部署防火墙状态采集（GuiZang 自定义）：每 30 分钟上报防火墙状态，供仪表盘"设备详情页"展示
FW="/Library/Ossec/guizang-firewall.sh"
[ -n "$AGENT_NOTE" ] && printf '%s\n' "$AGENT_NOTE" > /Library/Ossec/guizang-agent-note.txt
cat > "$FW" <<'FWEOF'
#!/bin/bash
en=unknown
state=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null)
echo "$state" | grep -qi "enabled" && en=on
echo "$state" | grep -qi "disabled" && en=off
echo "guizang_firewall enabled=$en domain=na private=na public=na realtime=unknown platform=macos"
FWEOF
chmod +x "$FW"
if [ -f "$CONF" ] && ! grep -q "guizang-firewall" "$CONF" 2>/dev/null; then
  cat >> "$CONF" <<'CFGEOF'
<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <command>/bin/bash /Library/Ossec/guizang-firewall.sh</command>
    <alias>guizang-firewall</alias>
    <frequency>1800</frequency>
  </localfile>
</ossec_config>
CFGEOF
fi

echo "[4/5] 注册到服务器 ..."
# 升级安装不会自动注册；若还没有有效密钥(client.keys)就用 agent-auth 注册。
# （开机自启由官方 pkg 安装的 LaunchDaemon 负责，无需手动设置）
KEYS="/Library/Ossec/etc/client.keys"
if [ ! -s "$KEYS" ]; then
  if [ -n "$REG_PASSWORD" ]; then
    /Library/Ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" -P "$REG_PASSWORD" || true
  else
    /Library/Ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || true
  fi
else
  echo "    已有注册密钥，跳过注册。"
fi

echo "[5/5] 启动服务 ..."
/Library/Ossec/bin/wazuh-control restart || /Library/Ossec/bin/wazuh-control start

echo
# 轮询等待服务就绪（慢机器上 agentd 启动需要几秒，单次检查易误报"未就绪"）
READY=0
for _ in $(seq 1 15); do
  if /Library/Ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
    READY=1; break
  fi
  sleep 2
done
if [ "$READY" -eq 1 ]; then
  echo "[OK] 安装完成，GuiZang 监控已运行并设为开机自启。"
  echo "     日志：/Library/Ossec/logs/ossec.log"
else
  echo "[!] 服务未就绪。请运行以下命令排查："
  echo "     sudo /Library/Ossec/bin/wazuh-control status"
  echo "     sudo tail -n 40 /Library/Ossec/logs/ossec.log"
  echo "     并确认能连到 ${MANAGER} 的 1514/1515 端口（nc -vz ${MANAGER} 1515）。"
fi

rm -f "${PKG:-}" /tmp/wazuh_envs
