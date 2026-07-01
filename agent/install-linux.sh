#!/bin/bash
# GuiZang - Linux 安全监控终端一键安装脚本（自动适配发行版，安装 Wazuh 官方仓库的最新版 Agent）
# 用法：
#   方式一（推荐）：先在下方【每客户改一次】填好服务器IP，然后零输入运行：
#         sudo bash install-linux.sh
#   方式二：临时指定： sudo bash install-linux.sh 192.168.1.10
set -euo pipefail

# ============================================================
#  【每客户改一次】把这里填成该客户服务器(Manager)的固定 IP，
#   之后所有 Linux 装机零输入。建议给服务器设静态 IP 或用域名。
DEFAULT_MANAGER=""        # 例：DEFAULT_MANAGER="192.168.1.10"
DEFAULT_REG_PASSWORD=""   # 一般留空：启用了注册密码时，运行时会提示你手动输入（不写进脚本更安全）
DEFAULT_VERSION=""        # 由 deploy.sh 自动填入服务器(Manager)版本以保持一致；留空=装仓库最新
# ============================================================

MANAGER="${1:-}"
AGENT_NAME="${2:-}"
REG_PASSWORD="${3:-$DEFAULT_REG_PASSWORD}"
# 版本：环境变量 WAZUH_VERSION > 脚本内默认(对齐 Manager) > 仓库最新（留空）
VER="${WAZUH_VERSION:-$DEFAULT_VERSION}"

if [ "$(id -u)" -ne 0 ]; then
  echo "需要管理员权限，请用 sudo 重新运行：sudo bash $0 $*"
  exit 1
fi

# 自动发现服务器：扫描本网段 1514 端口（通信端口）
find_manager() {
  command -v nc >/dev/null 2>&1 || return 0
  local ip prefix host
  ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [ -z "$ip" ] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [ -z "$ip" ] && return 0
  prefix="$(echo "$ip" | cut -d. -f1-3)"
  echo "[*] 未指定服务器地址，正在本网段 ${prefix}.0/24 搜索 GuiZang 服务器(端口1514) ..." >&2
  for h in $(seq 1 254); do
    ( nc -z -w 1 "${prefix}.${h}" 1514 >/dev/null 2>&1 && echo "${prefix}.${h}" ) &
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
[ -z "$MANAGER" ] && { echo "[X] 未确定 Manager 地址，退出。"; exit 1; }

# 注册密码：参数 > 脚本内默认 > 交互输入。
# 若服务器【启用了注册密码】，请在下面提示处粘贴管理员私下给你的密码后回车；
# 没启用密码就直接回车跳过即可。
if [ -z "$REG_PASSWORD" ]; then
  read -r -p "请输入【服务器注册密码】（没设密码就直接回车跳过）: " REG_PASSWORD || true
fi

# 终端自定义名称：参数 > 交互输入。多台电脑时便于在仪表盘快速识别（回车默认用机器名）。
if [ -z "$AGENT_NAME" ] && [ -t 0 ]; then
  DEFAULT_NAME="$(hostname -s 2>/dev/null || hostname)"
  read -r -p "请输入该终端的【自定义名称】，便于仪表盘识别（仅字母/数字/中划线，回车默认：${DEFAULT_NAME}）: " AGENT_NAME || true
  [ -z "$AGENT_NAME" ] && AGENT_NAME="$DEFAULT_NAME"
fi
# Wazuh 代理名只允许字母数字和 - _ . ；空格转 -，去掉中文等非法字符（否则注册被拒）
AGENT_NAME="$(printf '%s' "$AGENT_NAME" | tr ' ' '-' | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
[ -z "$AGENT_NAME" ] && AGENT_NAME="$(hostname -s 2>/dev/null | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
[ -z "$AGENT_NAME" ] && AGENT_NAME="linux-agent"

echo "==== GuiZang · Linux 安全监控终端 安装 ===="
echo "服务器    : $MANAGER"
echo "AgentName : $AGENT_NAME"
echo "版本      : ${VER:-仓库最新}"
echo

run_with_wazuh_env() {
  if [ -n "$REG_PASSWORD" ]; then
    env WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" WAZUH_REGISTRATION_PASSWORD="$REG_PASSWORD" "$@"
  else
    env WAZUH_MANAGER="$MANAGER" WAZUH_AGENT_NAME="$AGENT_NAME" "$@"
  fi
}

# ---------------------------------------------------------------- 1) 安装 Agent（按包管理器自适应）
install_via_apt() {
  echo "[1/4] 配置 Wazuh APT 仓库并安装最新版 Agent ..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y || true
  apt-get install -y ca-certificates curl gnupg apt-transport-https
  curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
  apt-get update -y
  run_with_wazuh_env apt-get install -y "wazuh-agent${VER:+=${VER}-1}"
}

install_via_yum() {
  echo "[1/4] 配置 Wazuh YUM 仓库并安装最新版 Agent ..."
  local PM="yum"
  command -v dnf >/dev/null 2>&1 && PM="dnf"
  $PM install -y ca-certificates curl gnupg2 2>/dev/null || $PM install -y ca-certificates curl 2>/dev/null || true
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null || true
  cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
  run_with_wazuh_env "$PM" install -y "wazuh-agent${VER:+-${VER}-1}"
}

install_via_zypper() {
  echo "[1/4] 配置 Wazuh zypper 仓库并安装最新版 Agent ..."
  zypper -n install ca-certificates curl gawk 2>/dev/null || true
  rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH 2>/dev/null || true
  cat > /etc/zypp/repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
  run_with_wazuh_env zypper -n install "wazuh-agent${VER:+=${VER}}"
}

if command -v apt-get >/dev/null 2>&1; then
  install_via_apt
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
  install_via_yum
elif command -v zypper >/dev/null 2>&1; then
  install_via_zypper
else
  echo "[X] 未识别的包管理器（非 apt/yum/dnf/zypper）。请手动安装 wazuh-agent。"
  exit 1
fi

# ---------------------------------------------------------------- 2) 兜底写入 Manager 地址
echo "[2/4] 写入服务器地址 ..."
CONF="/var/ossec/etc/ossec.conf"
if [ -f "$CONF" ]; then
  sed -i -E "s#<address>[^<]*</address>#<address>${MANAGER}</address>#" "$CONF" || true
fi

# 部署防火墙状态采集（GuiZang 自定义）：每 30 分钟上报防火墙状态，供仪表盘"设备详情页"展示
FW="/var/ossec/guizang-firewall.sh"
cat > "$FW" <<'FWEOF'
#!/bin/bash
en=unknown
if command -v ufw >/dev/null 2>&1; then
  ufw status 2>/dev/null | grep -qi "Status: active" && en=on || en=off
elif command -v firewall-cmd >/dev/null 2>&1; then
  [ "$(firewall-cmd --state 2>/dev/null)" = "running" ] && en=on || en=off
elif command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
  en=on
elif command -v nft >/dev/null 2>&1 && [ -n "$(nft list ruleset 2>/dev/null)" ]; then
  en=on
elif command -v iptables >/dev/null 2>&1; then
  [ "$(iptables -S 2>/dev/null | grep -c '^-A')" -gt 0 ] && en=on || en=off
fi
echo "guizang_firewall enabled=$en domain=na private=na public=na realtime=unknown platform=linux"
FWEOF
chmod +x "$FW"
if [ -f "$CONF" ] && ! grep -q "guizang-firewall" "$CONF" 2>/dev/null; then
  cat >> "$CONF" <<'CFGEOF'
<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <command>/bin/bash /var/ossec/guizang-firewall.sh</command>
    <alias>guizang-firewall</alias>
    <frequency>1800</frequency>
  </localfile>
</ossec_config>
CFGEOF
fi

# ---------------------------------------------------------------- 3) 注册（无有效密钥时）
echo "[3/4] 注册到服务器 ..."
KEYS="/var/ossec/etc/client.keys"
if [ ! -s "$KEYS" ]; then
  if [ -n "$REG_PASSWORD" ]; then
    /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" -P "$REG_PASSWORD" || true
  else
    /var/ossec/bin/agent-auth -m "$MANAGER" -A "$AGENT_NAME" || true
  fi
else
  echo "    已有注册密钥，跳过注册。"
fi

# ---------------------------------------------------------------- 4) 开机自启 + 启动
echo "[4/4] 启动服务并设为开机自启 ..."
systemctl daemon-reload 2>/dev/null || true
systemctl enable wazuh-agent 2>/dev/null || true
systemctl restart wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control restart || /var/ossec/bin/wazuh-control start

# 轮询等待服务就绪（慢机器上 agentd 启动需要几秒）
READY=0
for _ in $(seq 1 15); do
  if /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
    READY=1; break
  fi
  sleep 2
done
echo
if [ "$READY" -eq 1 ]; then
  echo "[OK] 安装完成，GuiZang 监控已运行并设为开机自启。"
  echo "     日志：/var/ossec/logs/ossec.log"
else
  echo "[!] 服务未就绪。请运行以下命令排查："
  echo "     sudo /var/ossec/bin/wazuh-control status"
  echo "     sudo tail -n 40 /var/ossec/logs/ossec.log"
  echo "     并确认能连到 ${MANAGER} 的 1514/1515 端口（nc -vz ${MANAGER} 1515）。"
fi
