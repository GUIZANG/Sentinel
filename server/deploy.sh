#!/bin/bash
# GuiZang - 服务端一键部署（Linux / macOS 本地测试）
# 一条命令完成：安装 Docker -> 内核参数 -> 生成证书 -> 启动 GuiZang 全部服务。
# 客户服务器无需预装任何东西（除操作系统外）。
set -euo pipefail

cd "$(dirname "$0")"
SERVER_DIR="$(pwd)"
ROOT_DIR="$(cd .. && pwd)"
SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo"
OS="$(uname -s)"   # Linux=服务器正式部署；Darwin=Mac 本地测试
if [ "$OS" = "Darwin" ]; then
  SUDO=""
fi

# 一键部署默认会把本机 Ollama/GuizangAI 也准备好；服务器已有独立模型服务时可设 ENABLE_LOCAL_GUIZANGAI=false。
ENABLE_LOCAL_GUIZANGAI="${ENABLE_LOCAL_GUIZANGAI:-true}"
AUTO_INSTALL_LOCAL_AGENT="${AUTO_INSTALL_LOCAL_AGENT:-true}"
GUIZANGAI_MODEL="${GUIZANGAI_MODEL:-qwen2.5:3b}"
GUIZANGAI_API_STYLE="${GUIZANGAI_API_STYLE:-ollama}"
GUIZANGAI_BASE_URL="${GUIZANGAI_BASE_URL:-http://host.docker.internal:11434}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION:-0}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

install_event() {
  local step="$1" status="$2" progress="$3" message="$4"
  printf 'INSTALL_EVENT={"step":"%s","status":"%s","progress":%s,"message":"%s"}\n' \
    "$(json_escape "$step")" "$(json_escape "$status")" "${progress}" "$(json_escape "$message")"
}

trap 'install_event "failed" "error" 100 "安装失败，请查看日志。"' ERR

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

set_env_key() {
  local key="$1" value="$2"
  if grep -q "^${key}=" .env; then
    sed -i.bak "s|^${key}=.*|${key}=${value}|" .env && rm -f .env.bak
  else
    echo "${key}=${value}" >> .env
  fi
}

env_value() {
  grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true
}

configure_one_click_env() {
  [ -f .env ] || return 0
  if [ "${ENABLE_LOCAL_GUIZANGAI}" = "true" ]; then
    [ -n "$(env_value GUIZANGAI_BASE_URL)" ] || set_env_key GUIZANGAI_BASE_URL "${GUIZANGAI_BASE_URL}"
    [ -n "$(env_value GUIZANGAI_API_STYLE)" ] || set_env_key GUIZANGAI_API_STYLE "${GUIZANGAI_API_STYLE}"
    [ -n "$(env_value GUIZANGAI_MODEL)" ] || set_env_key GUIZANGAI_MODEL "${GUIZANGAI_MODEL}"
    [ -n "$(env_value GUIZANGAI_TIMEOUT_SECONDS)" ] || set_env_key GUIZANGAI_TIMEOUT_SECONDS "120"
    [ -n "$(env_value GUIZANGAI_MAX_NEW_TOKENS)" ] || set_env_key GUIZANGAI_MAX_NEW_TOKENS "96"
    [ -n "$(env_value GUIZANGAI_TEMPERATURE)" ] || set_env_key GUIZANGAI_TEMPERATURE "0.2"
    [ -n "$(env_value GUIZANGAI_NUM_CTX)" ] || set_env_key GUIZANGAI_NUM_CTX "4096"
    [ -n "$(env_value GUIZANGAI_KEEP_ALIVE)" ] || set_env_key GUIZANGAI_KEEP_ALIVE "${OLLAMA_KEEP_ALIVE}"
    [ -n "$(env_value GUIZANGAI_NUM_GPU)" ] || set_env_key GUIZANGAI_NUM_GPU "999"
    [ -n "$(env_value GUIZANGAI_ANALYSIS_CONCURRENCY)" ] || set_env_key GUIZANGAI_ANALYSIS_CONCURRENCY "1"
    [ -n "$(env_value GUIZANGAI_ANALYSIS_CACHE_TTL_SECONDS)" ] || set_env_key GUIZANGAI_ANALYSIS_CACHE_TTL_SECONDS "600"
    [ -n "$(env_value GUIZANGAI_ADVICE_CACHE_TTL_SECONDS)" ] || set_env_key GUIZANGAI_ADVICE_CACHE_TTL_SECONDS "3600"
    [ -n "$(env_value GUIZANGAI_SEND_RAW_LOGS)" ] || set_env_key GUIZANGAI_SEND_RAW_LOGS "false"
    [ -n "$(env_value GUIZANGAI_RAW_LOGS_MAX)" ] || set_env_key GUIZANGAI_RAW_LOGS_MAX "20"
  fi
  [ -n "$(env_value ANALYSIS_INTERVAL_MINUTES)" ] || set_env_key ANALYSIS_INTERVAL_MINUTES "1"
  [ -n "$(env_value AUTH_SECRET)" ] || set_env_key AUTH_SECRET "$(random_hex)"
  [ -n "$(env_value DEFAULT_ADMIN_USER)" ] || set_env_key DEFAULT_ADMIN_USER "testadmin"
  [ -n "$(env_value DEFAULT_ADMIN_PASSWORD)" ] || set_env_key DEFAULT_ADMIN_PASSWORD "testpass"
  [ -n "$(env_value CORS_ORIGINS)" ] || set_env_key CORS_ORIGINS "http://localhost:${WEB_PORT:-8080},http://127.0.0.1:${WEB_PORT:-8080},http://${SERVER_IP:-127.0.0.1}:${WEB_PORT:-8080}"
  if [ -z "$(env_value AGENT_REG_PASSWORD)" ] && [ "${GUIZANG_AUTO_AGENT_PASSWORD:-1}" != "0" ]; then
    set_env_key AGENT_REG_PASSWORD "$(random_hex | cut -c 1-20)"
  fi
}

ensure_ollama_guizangai() {
  install_event "ollama" "running" 30 "准备本机 Ollama 与 AI 模型"
  [ "${ENABLE_LOCAL_GUIZANGAI}" = "true" ] || {
    echo "[*] 已跳过本机 GuizangAI/Ollama 准备（ENABLE_LOCAL_GUIZANGAI=${ENABLE_LOCAL_GUIZANGAI}）。"
    install_event "ollama" "skipped" 34 "已跳过本机 AI 准备"
    return 0
  }
  command -v curl >/dev/null 2>&1 || {
    echo "[!] 未找到 curl，跳过 GuizangAI 健康检查；BFF 调用失败时会自动回退 Mock。"
    return 0
  }

  if ! command -v ollama >/dev/null 2>&1; then
    if [ "$OS" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
      echo "[*] 未检测到 Ollama，正在通过 Homebrew 安装 ..."
      brew install ollama || true
    elif [ "$OS" = "Linux" ]; then
      echo "[*] 未检测到 Ollama，尝试安装本机 Ollama ..."
      curl -fsSL https://ollama.com/install.sh | sh || true
    fi
  fi
  if ! command -v ollama >/dev/null 2>&1; then
    echo "[!] 未找到 Ollama 命令；服务端会继续部署，AI 调用失败时会回退 Mock。"
    install_event "ollama" "warning" 34 "未安装 Ollama，继续部署核心服务"
    return 0
  fi

  if curl -fsS "${OLLAMA_BASE_URL}/api/tags" >/dev/null 2>&1; then
    echo "[*] 本机 Ollama/GuizangAI 服务已响应：${OLLAMA_BASE_URL}"
  else
    echo "[*] 正在启动本机 Ollama 服务（FlashAttention=${OLLAMA_FLASH_ATTENTION}, KeepAlive=${OLLAMA_KEEP_ALIVE}）..."
    OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION}" \
      OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE}" \
      nohup ollama serve >"${ROOT_DIR}/ollama.log" 2>&1 &
    for _ in $(seq 1 30); do
      curl -fsS "${OLLAMA_BASE_URL}/api/tags" >/dev/null 2>&1 && break
      sleep 2
    done
  fi

  if ! curl -fsS "${OLLAMA_BASE_URL}/api/tags" >/dev/null 2>&1; then
    echo "[!] GuizangAI 服务暂未响应；部署会继续，AI 调用失败时会回退 Mock。"
    install_event "ollama" "warning" 36 "Ollama 暂未响应，继续部署核心服务"
    return 0
  fi

  if ! ollama list | awk 'NR>1 {print $1}' | grep -Eq "^(${GUIZANGAI_MODEL}|${GUIZANGAI_MODEL}:latest)$"; then
    install_event "model" "running" 38 "正在拉取 AI 模型 ${GUIZANGAI_MODEL}"
    echo "[*] 未检测到 GuizangAI 模型 ${GUIZANGAI_MODEL}，正在通过 Ollama 拉取 ..."
    ollama pull "${GUIZANGAI_MODEL}" || {
      echo "[!] 模型拉取失败。请稍后手动执行：ollama pull ${GUIZANGAI_MODEL}"
      install_event "model" "warning" 42 "模型拉取失败，可稍后手动拉取"
      return 0
    }
  else
    echo "[*] 已检测到 GuizangAI 模型：${GUIZANGAI_MODEL}"
  fi
  install_event "model" "done" 45 "AI 模型准备完成"
}

local_agent_name() {
  local name
  name="$(scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || scutil --get ComputerName 2>/dev/null || hostname)"
  name="$(printf '%s' "${name}" | tr ' ' '-' | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
  [ -n "${name}" ] && printf '%s\n' "${name}" || printf 'macos-agent\n'
}

ensure_local_agent() {
  install_event "agent" "running" 88 "准备接入本机 Agent"
  [ "${AUTO_INSTALL_LOCAL_AGENT}" = "true" ] || {
    echo "[*] 已跳过本机 Agent 自动接入（AUTO_INSTALL_LOCAL_AGENT=${AUTO_INSTALL_LOCAL_AGENT}）。"
    install_event "agent" "skipped" 92 "已跳过本机 Agent 自动接入"
    return 0
  }
  [ "$OS" = "Darwin" ] || {
    echo "[*] 当前不是 macOS，跳过本机 Agent 自动安装。"
    install_event "agent" "skipped" 92 "当前平台跳过本机 Agent 自动安装"
    return 0
  }

  local agent_script="${SERVER_DIR}/agent-dist/install-macos.command"
  local agent_name conf
  agent_name="$(local_agent_name)"
  conf="/Library/Ossec/etc/ossec.conf"

  if [ -d "/Library/Ossec" ]; then
    echo "[*] 检测到本机已安装 Agent，自动更新服务器地址并重启 ..."
    if [ -f "${conf}" ]; then
      sudo /usr/bin/sed -i '' -E "s#<address>[^<]*</address>#<address>${SERVER_IP}</address>#" "${conf}" || true
    fi
    sudo /Library/Ossec/bin/wazuh-control restart || sudo /Library/Ossec/bin/wazuh-control start || true
    sudo /Library/Ossec/bin/wazuh-control status 2>/dev/null | grep -q "is running" \
      && echo "[*] 本机 Agent 已运行，数据会自动接入仪表盘。" \
      || echo "[!] 本机 Agent 重启命令已执行，稍后可在仪表盘查看在线状态。"
    install_event "agent" "done" 95 "本机 Agent 已更新并重启"
    return 0
  fi

  if [ ! -f "${agent_script}" ]; then
    echo "[!] 未找到本机 Agent 安装脚本：${agent_script}，跳过本机 Agent 自动接入。"
    return 0
  fi
  echo "[*] 本机还没有 Agent，开始自动安装并注册到 ${SERVER_IP} ..."
  chmod +x "${agent_script}"
  sudo bash "${agent_script}" "${SERVER_IP}" "${agent_name}" "${REG_PASSWORD:-}"
  install_event "agent" "done" 95 "本机 Agent 安装完成"
}

trigger_analysis_once() {
  command -v curl >/dev/null 2>&1 || return 0
  local base="http://${SERVER_IP}:${WEB_PORT}"
  local user password token
  user="$(env_value DEFAULT_ADMIN_USER)"; user="${user:-testadmin}"
  password="$(env_value DEFAULT_ADMIN_PASSWORD)"; password="${password:-testpass}"
  token="$(curl -fsS -X POST "${base}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "{\"username\":\"${user}\",\"password\":\"${password}\"}" \
    | sed -n 's/.*"token"[ ]*:[ ]*"\([^"]*\)".*/\1/p' 2>/dev/null || true)"
  if [ -z "${token}" ]; then
    echo "[!] 首轮 GuizangAI 分析会由 BFF 启动时自动触发；自动登录失败，跳过额外触发。"
    return 0
  fi
  echo "[*] 正在后台触发一轮 GuizangAI 分析，完成后会自动显示在仪表盘 ..."
  (
    curl -fsS -X POST "${base}/api/ai/run" -H "Authorization: Bearer ${token}" >/dev/null \
      && echo "[*] GuizangAI 分析完成，结果已写入仪表盘。" \
      || echo "[!] GuizangAI 分析触发失败；定时任务会继续自动重试。"
  ) &
}

# Agent 要连的地址：可用 ./deploy.sh <IP或域名> 手动指定，否则自动探测
# 注意：云服务器(阿里云/AWS等)必须手动传【公网IP或域名】，自动探测到的是内网IP！
ARG_ADDR="${1:-}"
SERVER_IP="$ARG_ADDR"
detect_ip() {
  local ip=""
  # Linux
  ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
  [ -z "$ip" ] && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  # macOS（本机测试时）
  [ -z "$ip" ] && ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
  echo "$ip"
}
is_private_ip() {
  case "$1" in
    10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|127.*) return 0 ;;
    *) return 1 ;;
  esac
}
[ -z "$SERVER_IP" ] && SERVER_IP="$(detect_ip)"

install_event "prepare" "running" 2 "开始 Sentinel 一键安装"
echo "==== GuiZang · 服务端一键部署 ===="
echo "    Agent 将连接的地址：${SERVER_IP:-未知}"

# 云服务器提醒：自动探测到内网 IP 且用户没手动指定时，尝试给出公网 IP 建议
if [ -z "$ARG_ADDR" ] && is_private_ip "${SERVER_IP:-}"; then
  PUB="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)"
  echo
  echo "    ⚠️  检测到这是内网 IP。如果这是【云服务器/租用服务器】，公司电脑无法用内网 IP 连接！"
  [ -n "$PUB" ] && echo "        本机公网 IP 可能是：$PUB"
  echo "        云服务器请改用公网IP或域名重跑，例如：  ./deploy.sh ${PUB:-<你的公网IP或域名>}"
  echo "        （内网/局域网部署可忽略此提示，直接继续）"
  read -r -p "    仍用 ${SERVER_IP} 继续吗？[y/N] " ipans
  if [ "${ipans:-N}" != "y" ] && [ "${ipans:-N}" != "Y" ]; then
    echo "    已取消。请用 ./deploy.sh <公网IP或域名> 重新运行。"; exit 0
  fi
fi

# ---------------------------------------------------------------- 1) Docker
add_macos_docker_to_path() {
  if [ "$OS" = "Darwin" ] && [ -d "/Applications/Docker.app" ]; then
    export PATH="/Applications/Docker.app/Contents/Resources/bin:$PATH"
  fi
}

wait_for_docker() {
  local waited=0
  local max_wait="${1:-180}"
  while ! docker info >/dev/null 2>&1; do
    if [ "$waited" -ge "$max_wait" ]; then
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
    echo "    等待 Docker 启动中... ${waited}/${max_wait}s"
  done
}

install_docker_desktop_macos() {
  echo "[*] 未检测到 Docker Desktop，开始自动下载安装 ..."

  if command -v brew >/dev/null 2>&1; then
    echo "    检测到 Homebrew，使用 brew 安装 Docker Desktop。"
    brew install --cask docker
  else
    echo "    未检测到 Homebrew，直接从 Docker 官方下载 dmg。"
    local arch url dmg mount_point
    arch="$(uname -m)"
    if [ "$arch" = "arm64" ]; then
      url="https://desktop.docker.com/mac/main/arm64/Docker.dmg"
    else
      url="https://desktop.docker.com/mac/main/amd64/Docker.dmg"
    fi
    dmg="/tmp/guizang-docker-desktop.dmg"
    mount_point="/Volumes/GuiZangDockerDesktop"

    command -v curl >/dev/null 2>&1 || { echo "[x] 缺少 curl，无法下载 Docker Desktop。"; exit 1; }
    rm -f "$dmg"
    hdiutil detach "$mount_point" >/dev/null 2>&1 || true
    curl -fL "$url" -o "$dmg"
    hdiutil attach "$dmg" -nobrowse -quiet -mountpoint "$mount_point"
    if [ -d "/Applications/Docker.app" ]; then
      rm -rf "/Applications/Docker.app" 2>/dev/null || sudo rm -rf "/Applications/Docker.app"
    fi
    ditto "${mount_point}/Docker.app" "/Applications/Docker.app" 2>/dev/null || sudo ditto "${mount_point}/Docker.app" "/Applications/Docker.app"
    hdiutil detach "$mount_point" >/dev/null 2>&1 || true
    rm -f "$dmg"
  fi

  add_macos_docker_to_path
  echo "    Docker Desktop 已安装，正在打开。首次启动可能需要你在弹窗中确认权限。"
  open -a Docker 2>/dev/null || true
  if ! wait_for_docker 240; then
    echo "[x] Docker Desktop 已安装但尚未就绪。请确认 Docker Desktop 弹窗权限后重跑本脚本。"
    exit 1
  fi
}

is_container_linux() {
  [ -f /.dockerenv ] && return 0
  grep -qaE '(docker|containerd|kubepods)' /proc/1/cgroup 2>/dev/null
}

install_linux_base_tools() {
  if command -v curl >/dev/null 2>&1 && [ -d /etc/ssl/certs ]; then
    return 0
  fi
  echo "[*] 安装基础下载依赖（curl/ca-certificates/gnupg）..."
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y ca-certificates curl gnupg lsb-release
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y ca-certificates curl gnupg
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y ca-certificates curl gnupg
  elif command -v zypper >/dev/null 2>&1; then
    $SUDO zypper --non-interactive install ca-certificates curl gpg2
  else
    echo "[x] 未识别的 Linux 包管理器，无法自动安装 curl。请先安装 curl 后重跑。"
    exit 1
  fi
  command -v curl >/dev/null 2>&1 || { echo "[x] curl 安装失败，无法继续自动部署。"; exit 1; }
}

install_docker_cli_only_linux() {
  echo "[*] 检测到容器测试环境已挂载 Docker socket，仅安装 Docker CLI 和 Compose 插件 ..."
  install_linux_base_tools
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | $SUDO tee /etc/apt/keyrings/docker.asc >/dev/null
    $SUDO chmod a+r /etc/apt/keyrings/docker.asc
    local codename
    codename="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${codename} stable" \
      | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null
    $SUDO apt-get update
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y docker-ce-cli docker-compose-plugin docker-buildx-plugin
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y dnf-plugins-core
    $SUDO dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    $SUDO dnf install -y docker-ce-cli docker-compose-plugin docker-buildx-plugin
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y yum-utils
    $SUDO yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    $SUDO yum install -y docker-ce-cli docker-compose-plugin docker-buildx-plugin
  else
    echo "[x] 当前容器环境不支持自动安装 Docker CLI。请使用 Ubuntu/CentOS/RHEL 容器测试。"
    exit 1
  fi
}

install_compose_plugin_linux() {
  echo "[*] 安装 docker compose 插件 ..."
  install_linux_base_tools
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y docker-compose-plugin
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y docker-compose-plugin
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y docker-compose-plugin
  elif command -v zypper >/dev/null 2>&1; then
    $SUDO zypper --non-interactive install docker-compose-plugin
  else
    echo "[x] 未识别的 Linux 包管理器，无法自动安装 docker compose 插件。"
    exit 1
  fi
}

install_docker() {
  if [ "$OS" = "Darwin" ]; then
    install_docker_desktop_macos
    return 0
  fi
  echo "[*] 未检测到 Docker，开始自动安装 ..."
  if is_container_linux && [ -S /var/run/docker.sock ]; then
    install_docker_cli_only_linux
    return 0
  fi
  install_linux_base_tools
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  $SUDO sh /tmp/get-docker.sh
  $SUDO systemctl enable --now docker 2>/dev/null || true
  rm -f /tmp/get-docker.sh
}

add_macos_docker_to_path
install_event "docker" "running" 8 "检查 Docker 与 Compose"
if ! command -v docker >/dev/null 2>&1; then
  install_docker
fi
# Docker 守护进程是否在运行
if ! docker info >/dev/null 2>&1; then
  if [ "$OS" = "Darwin" ]; then
    echo "[*] Docker Desktop 没有在运行，正在自动打开 ..."
    open -a Docker 2>/dev/null || true
    if ! wait_for_docker 180; then
      echo "[x] Docker Desktop 尚未就绪。请确认 Docker Desktop 已启动并完成权限授权后重跑本脚本。"
      exit 1
    fi
  else
    $SUDO systemctl start docker 2>/dev/null || true
  fi
fi
if ! docker info >/dev/null 2>&1; then
  echo "[x] Docker 已安装但守护进程不可用。"
  if [ -S /var/run/docker.sock ]; then
    echo "    检测到 /var/run/docker.sock，请确认当前用户有权限访问该 socket。"
  else
    echo "    请确认 Docker 服务已启动后重跑：sudo systemctl start docker"
  fi
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  if [ "$OS" = "Darwin" ]; then
    echo "[x] docker compose 不可用，请确认 Docker Desktop 已更新到较新版本。"; exit 1
  fi
  install_compose_plugin_linux
fi
echo "[1/5] Docker 就绪：$(docker --version)"
install_event "docker" "done" 20 "Docker 与 Compose 已就绪"

# ---------------------------------------------------------------- 2) 内核参数（Indexer 必需）
install_event "kernel" "running" 22 "设置 Indexer 所需内核参数"
if [ "$OS" = "Darwin" ]; then
  # Mac 上参数在 Docker Desktop 的 Linux 虚拟机里，用特权容器设置（当次会话生效）
  echo "[2/5] macOS：设置 Docker 虚拟机的 vm.max_map_count=262144 ..."
  docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || \
    echo "    （设置失败可忽略，较新 Docker Desktop 多数已满足要求）"
else
  CUR_MMC="$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)"
  if [ "${CUR_MMC:-0}" -lt 262144 ]; then
    echo "[2/5] 设置 vm.max_map_count=262144 ..."
    $SUDO sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
    if ! grep -q "vm.max_map_count" /etc/sysctl.conf 2>/dev/null; then
      echo "vm.max_map_count=262144" | $SUDO tee -a /etc/sysctl.conf >/dev/null 2>&1 || true
    fi
  else
    echo "[2/5] vm.max_map_count 已满足（$CUR_MMC）"
  fi
fi
install_event "kernel" "done" 26 "系统参数检查完成"

# ---------------------------------------------------------------- 3) .env
install_event "config" "running" 27 "生成并补齐 server/.env"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "[*] 已从模板生成 .env，并将自动补齐一键部署所需配置。"
fi
configure_one_click_env
install_event "config" "done" 29 "配置文件准备完成"

WEB_PORT="$(grep -E '^WEB_PORT=' .env | cut -d= -f2)"; WEB_PORT="${WEB_PORT:-8080}"
GUIZANGAI="$(grep -E '^GUIZANGAI_BASE_URL=' .env | cut -d= -f2 || true)"
GUIZANGAI_MODEL="$(grep -E '^GUIZANGAI_MODEL=' .env | cut -d= -f2 || true)"; GUIZANGAI_MODEL="${GUIZANGAI_MODEL:-qwen2.5:3b}"
GUIZANGAI_API_STYLE="$(grep -E '^GUIZANGAI_API_STYLE=' .env | cut -d= -f2 || true)"; GUIZANGAI_API_STYLE="${GUIZANGAI_API_STYLE:-ollama}"
REG_PASSWORD="$(grep -E '^AGENT_REG_PASSWORD=' .env | cut -d= -f2- || true)"
DB_PORT="$(grep -E '^DB_PORT=' .env | cut -d= -f2)"; DB_PORT="${DB_PORT:-5432}"
DB_USER="$(grep -E '^POSTGRES_USER=' .env | cut -d= -f2)"; DB_USER="${DB_USER:-sentinel}"
DB_PASS="$(grep -E '^POSTGRES_PASSWORD=' .env | cut -d= -f2-)"; DB_PASS="${DB_PASS:-sentinel}"
DB_NAME="$(grep -E '^POSTGRES_DB=' .env | cut -d= -f2)"; DB_NAME="${DB_NAME:-sentinel}"
WAZUH_API_USER="$(grep -E '^WAZUH_API_USER=' .env | cut -d= -f2-)"; WAZUH_API_USER="${WAZUH_API_USER:-wazuh-wui}"
WAZUH_API_PASSWORD="$(grep -E '^WAZUH_API_PASSWORD=' .env | cut -d= -f2-)"; WAZUH_API_PASSWORD="${WAZUH_API_PASSWORD:-MyS3cr37P450r.*-}"
INDEXER_USER="$(grep -E '^INDEXER_USER=' .env | cut -d= -f2-)"; INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASSWORD="$(grep -E '^INDEXER_PASSWORD=' .env | cut -d= -f2-)"; INDEXER_PASSWORD="${INDEXER_PASSWORD:-SecretPassword}"

# ---------------------------------------------------------------- 3.5) Agent 注册密码（authd）
# .env 没设时交互询问；启用后：改 manager 配置 + 注入 Agent 脚本 + 部署后写 authd.pass
if [ -z "${REG_PASSWORD}" ]; then
  echo
  echo "[?] 是否启用 Agent 注册密码（authd）？可防止陌生设备乱注册，公网/云服务器强烈建议启用。"
  read -r -p "    启用？[y/N] " regans
  if [ "${regans:-N}" = "y" ] || [ "${regans:-N}" = "Y" ]; then
    read -r -p "    自定义密码请直接输入（留空则自动生成随机密码）： " reginput
    if [ -n "$reginput" ]; then
      REG_PASSWORD="$reginput"
    else
      REG_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
      echo "    已生成随机注册密码，并已写入 .env。"
    fi
    # 持久化到 .env
    if grep -q '^AGENT_REG_PASSWORD=' .env; then
      sed -i.bak "s|^AGENT_REG_PASSWORD=.*|AGENT_REG_PASSWORD=${REG_PASSWORD}|" .env && rm -f .env.bak
    else
      echo "AGENT_REG_PASSWORD=${REG_PASSWORD}" >> .env
    fi
  fi
fi

# 启用注册密码：把 manager 配置里的 use_password 置为 yes（幂等）
if [ -n "${REG_PASSWORD}" ]; then
  sed -i.bak 's|<use_password>no</use_password>|<use_password>yes</use_password>|' \
    config/wazuh_cluster/wazuh_manager.conf && rm -f config/wazuh_cluster/wazuh_manager.conf.bak
  echo "[*] 已启用 Agent 注册密码（authd）。"
fi

# ---------------------------------------------------------------- 3.6) 仪表盘登录令牌密钥（AUTH_SECRET）
# 为空则自动生成随机长串写入 .env，避免使用可被伪造的默认密钥（安全必需）。
AUTH_SECRET="$(grep -E '^AUTH_SECRET=' .env | cut -d= -f2- || true)"
if [ -z "${AUTH_SECRET}" ]; then
  AUTH_SECRET="$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  if grep -q '^AUTH_SECRET=' .env; then
    sed -i.bak "s|^AUTH_SECRET=.*|AUTH_SECRET=${AUTH_SECRET}|" .env && rm -f .env.bak
  else
    echo "AUTH_SECRET=${AUTH_SECRET}" >> .env
  fi
  echo "[*] 已自动生成仪表盘登录密钥 AUTH_SECRET 并写入 .env。"
fi

# ---------------------------------------------------------------- 3.7) 本机 GuizangAI/Ollama（可通过 ENABLE_LOCAL_GUIZANGAI=false 跳过）
ensure_ollama_guizangai

# ---------------------------------------------------------------- 4) 生成"已填好 IP"的 Agent 脚本 + 下载页
#    （必须在 docker compose up 之前生成，agent-dist 会被挂进 web 容器对外提供下载）
install_event "agent_dist" "running" 47 "生成 Agent 安装包与下载页"
echo "[3/6] 生成 Agent 安装包与下载页 ..."
mkdir -p agent-dist
# 先注入 IP
sed "s|^\$DefaultManager = \"\"|\$DefaultManager = \"${SERVER_IP}\"|" \
  ../agent/install-windows.ps1 > agent-dist/install-windows.ps1
sed "s|^DEFAULT_MANAGER=\"\"|DEFAULT_MANAGER=\"${SERVER_IP}\"|" \
  ../agent/install-macos.command > agent-dist/install-macos.command
sed "s|^DEFAULT_MANAGER=\"\"|DEFAULT_MANAGER=\"${SERVER_IP}\"|" \
  ../agent/install-linux.sh > agent-dist/install-linux.sh
cp ../agent/uninstall-windows.ps1 ../agent/diagnose-windows.ps1 agent-dist/ 2>/dev/null || true
cp ../agent/uninstall-macos.command ../agent/diagnose-macos.command agent-dist/ 2>/dev/null || true
cp ../agent/uninstall-linux.sh ../agent/diagnose-linux.sh agent-dist/ 2>/dev/null || true
cp ../installers/bootstrap/install-windows-ui.ps1 ../installers/bootstrap/install-macos-ui.command ../installers/bootstrap/install-linux-ui.sh agent-dist/ 2>/dev/null || true
rm -rf agent-dist/installer-ui
mkdir -p agent-dist/installer-ui
cp ../installer-ui/index.html ../installer-ui/installer_server.py agent-dist/installer-ui/ 2>/dev/null || true
# 注意：出于安全考虑，【不把注册密码写进下载页脚本】（下载页是公开的，写进去等于泄露密码）。
# 启用密码时，安装脚本会在运行时【提示安装人员手动输入】，密码由你私下告知装机人员。
# 注入服务器(Manager)版本，让 Agent 默认装与服务器一致的版本（Wazuh 要求 Agent ≤ Manager）
MGR_VERSION="$(grep -E 'wazuh/wazuh-manager:[0-9]' docker-compose.yml | sed -E 's|.*wazuh-manager:([0-9.]+).*|\1|' | head -1)"
if [ -n "${MGR_VERSION}" ]; then
  sed -i.bak "s|^\$DefaultVersion = \"\"|\$DefaultVersion = \"${MGR_VERSION}\"|" agent-dist/install-windows.ps1 && rm -f agent-dist/install-windows.ps1.bak
  sed -i.bak "s|^DEFAULT_VERSION=\"\"|DEFAULT_VERSION=\"${MGR_VERSION}\"|" agent-dist/install-macos.command && rm -f agent-dist/install-macos.command.bak
  sed -i.bak "s|^DEFAULT_VERSION=\"\"|DEFAULT_VERSION=\"${MGR_VERSION}\"|" agent-dist/install-linux.sh && rm -f agent-dist/install-linux.sh.bak
  echo "[*] Agent 默认版本已对齐 Manager：${MGR_VERSION}"
fi
chmod +x agent-dist/install-macos.command agent-dist/install-linux.sh agent-dist/uninstall-macos.command agent-dist/uninstall-linux.sh agent-dist/diagnose-macos.command agent-dist/diagnose-linux.sh agent-dist/install-macos-ui.command agent-dist/install-linux-ui.sh agent-dist/installer-ui/installer_server.py 2>/dev/null || true
cp ../agent/README.md agent-dist/README.md 2>/dev/null || true

# 复制预构建的原生安装包（若已用 installers/build-*.sh 构建好），并准备下载按钮 HTML
WIN_EXE_HTML=""; MAC_PKG_HTML=""
if [ -f ../installers/dist/GuiZangAgent.exe ]; then
  cp ../installers/dist/GuiZangAgent.exe agent-dist/
  WIN_EXE_HTML='<a class="btn" href="GuiZangAgent.exe" download>⬇ 双击安装程序 GuiZangAgent.exe</a>'
fi
if [ -f ../installers/dist/GuiZangAgent-macos-arm64.pkg ]; then
  cp ../installers/dist/GuiZangAgent-macos-arm64.pkg agent-dist/
  MAC_PKG_HTML="${MAC_PKG_HTML}"'<a class="btn" href="GuiZangAgent-macos-arm64.pkg" download>⬇ .pkg（Apple 芯片）</a>'
fi
if [ -f ../installers/dist/GuiZangAgent-macos-intel64.pkg ]; then
  cp ../installers/dist/GuiZangAgent-macos-intel64.pkg agent-dist/
  MAC_PKG_HTML="${MAC_PKG_HTML}"'<a class="btn" href="GuiZangAgent-macos-intel64.pkg" download>⬇ .pkg（Intel 芯片）</a>'
fi
(
  cd agent-dist
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 install-* uninstall-* diagnose-* installer-ui/* GuiZangAgent* 2>/dev/null > SHA256SUMS || true
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum install-* uninstall-* diagnose-* installer-ui/* GuiZangAgent* 2>/dev/null > SHA256SUMS || true
  fi
)

# 生成下载落地页：其它电脑浏览器打开 http://<IP>:<PORT>/download/ 即可看到一键命令
DLBASE="http://${SERVER_IP:-服务器IP}:${WEB_PORT}/download"
# 是否启用了注册密码，决定下载页展示哪种密码说明
if [ -n "${REG_PASSWORD}" ]; then
  PASS_NOTE='<div class="callout"><b>本服务器已启用「注册密码」。</b>运行上面任意一条命令后，脚本会停下来并显示一行提示：<br><code>请输入【服务器注册密码】（没设密码就直接回车跳过）</code><br>这时把<b>管理员私下发给你的注册密码</b>粘贴进去，按回车继续即可（Windows 同理，会弹出 <code>如有【服务器注册密码】请输入</code>）。出于安全，密码<b>不会写进下载脚本</b>，请勿在本页公开询问密码。</div>'
  PASS_HINT='<p class="muted">↑ 运行后按提示输入注册密码（看到「请输入【服务器注册密码】」时粘贴密码回车）。</p>'
else
  PASS_NOTE='<div class="callout">本服务器<b>未启用</b>注册密码，安装时看到「请输入【服务器注册密码】」提示直接<b>回车跳过</b>即可。</div>'
  PASS_HINT='<p class="muted">↑ 运行后若出现「请输入【服务器注册密码】」提示，直接回车跳过。</p>'
fi
cat > agent-dist/index.html <<HTML
<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GuiZang · 安全监控终端 安装</title>
<style>body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#0b1020;color:#e7ecf6;max-width:820px;margin:0 auto;padding:28px}
h1{font-size:22px}h2{font-size:17px;margin-top:28px;color:#4cc9f0}code,pre{background:#141d36;border:1px solid #243152;border-radius:8px}
pre{padding:14px;overflow:auto;white-space:pre-wrap;word-break:break-all}code{padding:2px 6px}
a.btn{display:inline-block;margin:8px 10px 0 0;padding:10px 16px;background:#4cc9f0;color:#06101f;font-weight:700;border-radius:8px;text-decoration:none}
.callout{margin:18px 0;padding:14px 16px;background:#15233f;border:1px solid #2d6cdf;border-left:4px solid #4cc9f0;border-radius:8px;line-height:1.7}
.callout code{background:#0b1020;border-color:#2d6cdf}
.muted{color:#8a98b8}</style></head><body>
<h1>GuiZang · 安全监控终端 安装</h1>
<p class="muted">在需要监控的电脑上安装。服务器地址：${SERVER_IP:-请手动确认}（脚本/安装包已自动配置）。三种系统都会自动下载所需 Agent 安装包和基础依赖。</p>
${PASS_NOTE}
<h2>可视化一键安装（核心系统）</h2>
<p class="muted">用于在当前电脑上安装 Docker、Ollama/AI 模型、核心服务和本机 Agent。下载后以管理员权限运行，会自动打开本机浏览器展示安装进度。若失败，可继续使用下面的命令行安装方式。</p>
<a class="btn" href="install-windows-ui.ps1" download>Windows 可视化安装器</a>
<a class="btn" href="install-macos-ui.command" download>macOS 可视化安装器</a>
<a class="btn" href="install-linux-ui.sh" download>Linux 可视化安装器</a>

${WIN_EXE_HTML:+<h2>Windows · 双击安装（推荐，给不熟电脑的同事）</h2><p class="muted">下载后双击运行，按提示允许管理员权限即可。</p>${WIN_EXE_HTML}}

<h2>Windows · 命令行安装</h2>
<p class="muted">管理员 PowerShell 里粘贴一条命令；脚本会自动下载 Windows Agent MSI 并安装：</p>
<pre>powershell -ExecutionPolicy Bypass -Command "iwr ${DLBASE}/install-windows.ps1 -OutFile \$env:TEMP\install-agent.ps1; & \$env:TEMP\install-agent.ps1"</pre>
${PASS_HINT}
<a class="btn" href="install-windows.ps1" download>下载 install-windows.ps1</a>
${MAC_PKG_HTML:+<h2>macOS · 双击安装（推荐，给不熟电脑的同事）</h2><p class="muted">下载对应芯片的安装包，双击运行（被拦截时右键→打开）。</p>${MAC_PKG_HTML}}

<h2>macOS · 命令行安装</h2>
<p class="muted">终端里粘贴一条命令；脚本会自动下载对应芯片的 macOS Agent pkg 并安装：</p>
<pre>curl -fsSL ${DLBASE}/install-macos.command -o /tmp/install-agent.command && sudo bash /tmp/install-agent.command</pre>
<p class="muted">备注：macOS 默认使用 <code>LocalHostName</code> 作为仪表盘里的 Agent 名，安装前会打印「将注册为：xxx」。如需临时指定名称和备注，可用：<br><code>sudo AGENT_NOTE="财务部前台 Mac" bash /tmp/install-agent.command ${SERVER_IP} 自定义Agent名</code></p>
${PASS_HINT}
<a class="btn" href="install-macos.command" download>下载 install-macos.command</a>

<h2>Linux · 命令行安装（自动适配 Ubuntu/Debian/CentOS/RHEL/SUSE）</h2>
<p class="muted">终端里粘贴一条命令（自动安装 curl/证书/仓库配置，并下载 Wazuh 官方 Agent）：</p>
<pre>curl -fsSL ${DLBASE}/install-linux.sh -o /tmp/install-agent.sh && sudo bash /tmp/install-agent.sh</pre>
${PASS_HINT}
<a class="btn" href="install-linux.sh" download>下载 install-linux.sh</a>

<h2>安装后检查</h2>
<p class="muted">安装脚本结束后，终端应出现 <code>[OK] 安装完成</code> 或服务运行提示。然后刷新 GuiZang 仪表盘首页，查看「终端席位总览」里的「最近新增终端」；如果显示在线，说明注册、心跳和数据上报都已打通。</p>
<p class="muted">如果没有出现新终端，请确认安装终端里打印的「将注册为：xxx」名称，并检查服务器地址、注册密码、1514/1515 端口连通性。</p>

<h2>诊断与卸载</h2>
<p class="muted">排障时先运行诊断脚本，确认服务状态、Manager 地址、1514/1515 连通性和最近日志。卸载脚本会停止服务并移除 Agent 主程序。</p>
<p>
  <a class="btn" href="diagnose-windows.ps1" download>Windows 诊断</a>
  <a class="btn" href="diagnose-macos.command" download>macOS 诊断</a>
  <a class="btn" href="diagnose-linux.sh" download>Linux 诊断</a>
</p>
<p>
  <a class="btn" href="uninstall-windows.ps1" download>Windows 卸载</a>
  <a class="btn" href="uninstall-macos.command" download>macOS 卸载</a>
  <a class="btn" href="uninstall-linux.sh" download>Linux 卸载</a>
</p>
<p class="muted">下载完整性校验文件：<a href="SHA256SUMS" download>SHA256SUMS</a></p>

<p class="muted" style="margin-top:28px">提示：Windows 务必"以管理员身份运行"；macOS 会要求输入管理员密码；Linux 需 sudo。未签名安装包被拦截时：右键→打开 / 更多信息→仍要运行。</p>
</body></html>
HTML
install_event "agent_dist" "done" 55 "Agent 下载页生成完成"

# ---------------------------------------------------------------- 5) 生成证书（仅首次）
install_event "certs" "running" 57 "检查或生成服务证书"
if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  echo "[4/6] 生成安全证书 ..."
  $SUDO docker compose -f generate-indexer-certs.yml run --rm generator
else
  echo "[4/6] 证书已存在，跳过生成"
fi
install_event "certs" "done" 62 "证书准备完成"

# ---------------------------------------------------------------- 6) 启动
install_event "compose" "running" 64 "构建并启动核心服务"
echo "[5/6] 构建并启动全部服务（GuiZang 引擎 + 数据库 + 后端 + 仪表盘）..."
$SUDO docker compose up -d --build
install_event "compose" "done" 78 "核心服务已启动"

install_event "healthcheck" "running" 80 "等待服务健康检查"
echo "[6/6] 等待服务就绪（Indexer 启动较慢，约 1-2 分钟）..."
sleep 15

# 启用注册密码时：把密码写入 manager 的 authd.pass 并重启 manager 生效
if [ -n "${REG_PASSWORD}" ]; then
  echo "[*] 写入 Agent 注册密码到 Manager ..."
  $SUDO docker compose exec -T wazuh.manager sh -c "printf '%s' '${REG_PASSWORD}' > /var/ossec/etc/authd.pass" 2>/dev/null || \
    echo "    （manager 尚未就绪，稍后会自动应用配置；也可稍后手动重跑本步骤）"
  $SUDO docker compose restart wazuh.manager >/dev/null 2>&1 || true
fi

health_url() {
  local name="$1" url="$2" extra="${3:-}"
  if eval "curl -fsS ${extra} '${url}' >/dev/null"; then
    echo "    [OK] ${name}"
    return 0
  fi
  echo "    [X]  ${name}：${url}"
  return 1
}

health_wazuh_api() {
  local waited=0
  while [ "$waited" -le 60 ]; do
    if curl -k -fsS -u "${WAZUH_API_USER:-wazuh-wui}:${WAZUH_API_PASSWORD:-MyS3cr37P450r.*-}" \
      -X POST "https://127.0.0.1:55000/security/user/authenticate" >/dev/null 2>&1; then
      echo "    [OK] Wazuh API 登录"
      return 0
    fi
    if [ "$waited" -eq 0 ]; then
      echo "    Wazuh API 尚未就绪，开始重试（最多 60 秒）..."
    fi
    sleep 5
    waited=$((waited + 5))
  done
  echo "    [X]  Wazuh API 登录：https://127.0.0.1:55000/security/user/authenticate"
  return 1
}

run_health_checks() {
  local failed=0 indexer_health
  command -v curl >/dev/null 2>&1 || {
    echo "[!] 未检测到 curl，跳过最终健康检查。"
    return 0
  }
  echo "[*] 最终健康检查 ..."
  health_url "Web 仪表盘" "http://127.0.0.1:${WEB_PORT}/" || failed=$((failed + 1))
  health_url "BFF /api/auth/exists" "http://127.0.0.1:${WEB_PORT}/api/auth/exists" || failed=$((failed + 1))
  health_url "下载页 /download/" "http://127.0.0.1:${WEB_PORT}/download/" || failed=$((failed + 1))
  health_wazuh_api || failed=$((failed + 1))
  indexer_health="$(curl -k -fsS -u "${INDEXER_USER:-admin}:${INDEXER_PASSWORD:-SecretPassword}" "https://127.0.0.1:9200/_cluster/health" 2>/dev/null || true)"
  if echo "$indexer_health" | grep -Eq '"status"[ ]*:[ ]*"(green|yellow)"'; then
    echo "    [OK] Indexer 集群状态：$(echo "$indexer_health" | sed -n 's/.*"status"[ ]*:[ ]*"\([^"]*\)".*/\1/p')"
  else
    echo "    [X]  Indexer 集群状态：未达到 green/yellow"
    failed=$((failed + 1))
  fi
  if [ "$failed" -gt 0 ]; then
    echo "    健康检查发现 ${failed} 项异常。请先看上面 [X] 项，再运行：docker compose logs -f bff wazuh.manager wazuh.indexer"
  fi
}

open_browser_after_deploy() {
  local dashboard="http://${SERVER_IP:-127.0.0.1}:${WEB_PORT}"
  if [ "${GUIZANG_NO_OPEN_BROWSER:-}" = "1" ]; then
    return 0
  fi
  echo "[*] 尝试自动打开仪表盘 ..."
  if [ "$OS" = "Darwin" ] && command -v open >/dev/null 2>&1; then
    open "$dashboard" >/dev/null 2>&1 || true
  elif command -v xdg-open >/dev/null 2>&1 && [ -n "${DISPLAY:-}" ]; then
    xdg-open "$dashboard" >/dev/null 2>&1 || true
  else
    echo "    当前环境没有可用图形浏览器，已跳过自动打开。"
  fi
}

$SUDO docker compose ps
run_health_checks
install_event "healthcheck" "done" 86 "健康检查完成"
open_browser_after_deploy
ensure_local_agent || true
trigger_analysis_once || true
install_event "done" "done" 100 "安装完成"

echo
echo "=================================================================="
echo "  [OK] 部署完成！"
echo "=================================================================="
echo
echo "   ★★★  Agent 该填的 IP 就是： ${SERVER_IP:-<请手动确认服务器IP>}  ★★★"
echo
echo "   GuiZang 仪表盘：  http://${SERVER_IP:-<服务器IP>}:${WEB_PORT}"
echo
echo "   数据库(存 GuizangAI/AI 分析历史 · 后台管理员可连)："
echo "     类型/地址 : PostgreSQL  ${SERVER_IP:-<服务器IP>}:${DB_PORT}"
echo "     库名/用户 : ${DB_NAME} / ${DB_USER}"
echo "     主要数据表: analysis_snapshots(AI分析快照) · metric_snapshots(指标趋势)"
echo "     连接方式  : 默认仅服务器本机可连；如需远程访问请使用 SSH 隧道。"
if is_private_ip "${SERVER_IP:-}"; then :; else
  echo "     ⚠️ 公网环境：请改强密码，并在云安全组只放行可信 IP 访问 ${DB_PORT} 端口！"
fi
echo "   ★ 在其它电脑上装 Agent：用浏览器打开下面这个【下载页】，照着粘一条命令即可"
echo "       下载页： http://${SERVER_IP:-<服务器IP>}:${WEB_PORT}/download/"
echo
echo "     Windows（管理员 PowerShell 粘贴）："
echo "       powershell -ExecutionPolicy Bypass -Command \"iwr http://${SERVER_IP:-<服务器IP>}:${WEB_PORT}/download/install-windows.ps1 -OutFile \$env:TEMP\\install-agent.ps1; & \$env:TEMP\\install-agent.ps1\""
echo "     macOS（终端粘贴）："
echo "       curl -fsSL http://${SERVER_IP:-<服务器IP>}:${WEB_PORT}/download/install-macos.command -o /tmp/install-agent.command && sudo bash /tmp/install-agent.command"
echo "     Linux（终端粘贴，自动适配发行版）："
echo "       curl -fsSL http://${SERVER_IP:-<服务器IP>}:${WEB_PORT}/download/install-linux.sh -o /tmp/install-agent.sh && sudo bash /tmp/install-agent.sh"
echo
echo "   （也可在服务器本地取脚本：$(pwd)/agent-dist/）"
if [ -n "${REG_PASSWORD}" ]; then
  echo
  echo "   🔐 已启用 Agent 注册密码（已保存到 server/.env 的 AGENT_REG_PASSWORD）。"
  echo "      为安全起见，此密码【不写进下载脚本】。装机时脚本会提示"
  echo "      『请输入【服务器注册密码】』，把此密码私下发给装机同事手动粘贴即可。"
  echo "      （请妥善保管 .env；下载页也已写明如何输入）"
fi
if [ -z "${GUIZANGAI}" ]; then
  echo "   GuizangAI：当前 Mock 模式。"
else
  echo "   GuizangAI：已配置 ${GUIZANGAI}"
fi
echo "=================================================================="
echo
echo "查看日志：docker compose logs -f bff wazuh.manager"
