#!/bin/bash
# 在【macOS】上构建 GuiZang 的安全监控终端安装包（.pkg，双击安装）。
# 原理：下载底层 agent pkg，在其 postinstall 末尾追加"设置服务器地址并启动"的逻辑后重打包。
# 产物：installers/dist/GuiZangAgent-macos-arm64.pkg 和 -intel64.pkg
set -euo pipefail

WAZUH_VERSION="${WAZUH_VERSION:-4.14.5}"   # 须与服务器 Manager 版本一致
cd "$(dirname "$0")"
DIST="$(cd ../.. && pwd)/installers/dist"
mkdir -p "$DIST"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 追加到官方 postinstall 末尾的"定制段"：发现/输入 Manager → 写配置 → 启动
read -r -d '' SENTINEL_BLOCK <<'BLOCK' || true

# ================= GuiZang 定制：设置服务器地址并启动 =================
SENTINEL_CONF="/Library/Ossec/etc/ossec.conf"
CONSOLE_USER=$(stat -f%Su /dev/console 2>/dev/null || echo "")
CONSOLE_UID=$(id -u "$CONSOLE_USER" 2>/dev/null || echo "")
ask_user() {  # $1=提示文字，返回用户输入
  [ -z "$CONSOLE_UID" ] && return 0
  launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" /usr/bin/osascript \
    -e "display dialog \"$1\" default answer \"\" buttons {\"确定\"} default button 1 with title \"GuiZang 安全监控\"" \
    -e "text returned of result" 2>/dev/null || true
}
# 1) 自动发现同网段的 Manager(1514 端口)
MGR=""
MYIP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "")
if [ -n "$MYIP" ]; then
  PREFIX=$(echo "$MYIP" | cut -d. -f1-3)
  for h in $(seq 1 254); do
    ( nc -z -G 1 -w 1 "${PREFIX}.${h}" 1514 >/dev/null 2>&1 && echo "${PREFIX}.${h}" ) &
  done > /tmp/.sentinel_scan 2>/dev/null
  wait
  MGR=$(grep -v "^${MYIP}$" /tmp/.sentinel_scan 2>/dev/null | head -1 || true)
  rm -f /tmp/.sentinel_scan
fi
# 2) 没发现则弹窗让安装人员输入
[ -z "$MGR" ] && MGR=$(ask_user "请输入安全服务器(Manager)的 IP 或域名：")
# 3) 注册密码（没有就留空）
PASS=$(ask_user "如有 Agent 注册密码请输入，没有请留空：")
# 4) 写入配置、注册并启动
if [ -n "$MGR" ]; then
  /usr/bin/sed -i '' -E "s#<address>[^<]*</address>#<address>${MGR}</address>#" "$SENTINEL_CONF" 2>/dev/null || true
  # 代理名清洗：Wazuh 只允许字母数字和 - _ . ；空格转 -，去掉中文等非法字符
  ANAME="$(scutil --get ComputerName 2>/dev/null || hostname)"
  ANAME="$(printf '%s' "$ANAME" | tr ' ' '-' | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
  [ -z "$ANAME" ] && ANAME="macos-agent"
  # 无有效密钥时注册到服务器（带密码则附加 -P）
  if [ ! -s /Library/Ossec/etc/client.keys ]; then
    if [ -n "$PASS" ]; then
      /Library/Ossec/bin/agent-auth -m "$MGR" -A "$ANAME" -P "$PASS" 2>/dev/null || true
    else
      /Library/Ossec/bin/agent-auth -m "$MGR" -A "$ANAME" 2>/dev/null || true
    fi
  fi
  /Library/Ossec/bin/wazuh-control restart 2>/dev/null || /Library/Ossec/bin/wazuh-control start 2>/dev/null || true
fi
# ================= /GuiZang 定制 =================
BLOCK

build_one() {
  local arch="$1"
  echo "==> 构建 ${arch} ..."
  local url="https://packages.wazuh.com/4.x/macos/wazuh-agent-${WAZUH_VERSION}-1.${arch}.pkg"
  local raw="$WORK/wazuh-${arch}.pkg"
  curl -fsSL -o "$raw" "$url"
  local exp="$WORK/exp-${arch}"
  pkgutil --expand "$raw" "$exp"
  # 定位 postinstall（兼容旧版 agent.pkg/Scripts 与新版顶层 Scripts 结构）
  local post
  post="$(find "$exp" -type f -path '*Scripts/postinstall' | head -1)"
  if [ -z "$post" ]; then echo "[X] 在 pkg 里找不到 postinstall，结构可能又变了。"; exit 1; fi
  # 追加定制段到 postinstall
  printf '%s\n' "$SENTINEL_BLOCK" >> "$post"
  # 重新打包
  local out="$DIST/GuiZangAgent-macos-${arch}.pkg"
  pkgutil --flatten "$exp" "$out"
  echo "    生成：$out"
}

build_one "arm64"     # Apple 芯片(M 系列)
build_one "intel64"   # Intel 芯片

echo
echo "[OK] 完成。产物在：$DIST"
ls -lh "$DIST"/*.pkg
echo
echo "提示：这是未签名安装包，双击若被拦截，请右键 → 打开，或系统设置 → 隐私与安全性 → 仍要打开。"
