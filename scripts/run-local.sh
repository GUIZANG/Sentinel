#!/usr/bin/env bash
# 一键启动：Sentinel/Wazuh 采集链路 -> 本地 GuizangAI 分析 -> 仪表盘。
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="${ROOT_DIR}/server"
ENV_FILE="${SERVER_DIR}/.env"
ENV_EXAMPLE="${SERVER_DIR}/.env.example"

# 自动探测本机局域网 IPv4（供 Agent 回连 / 仪表盘访问使用）。
# 优先走默认路由对应网卡，避免取到回环或虚拟网卡地址。
detect_lan_ip() {
  local ip="" iface i
  if [ "$(uname -s)" = "Darwin" ]; then
    iface="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || true)"
    [ -n "${iface}" ] && ip="$(ipconfig getifaddr "${iface}" 2>/dev/null || true)"
    if [ -z "${ip}" ]; then
      for i in en0 en1 en2 en3; do
        ip="$(ipconfig getifaddr "${i}" 2>/dev/null || true)"
        [ -n "${ip}" ] && break
      done
    fi
  else
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    [ -z "${ip}" ] && ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
  # 过滤掉回环 / 空值
  case "${ip}" in
    ""|127.*|::1) ip="" ;;
  esac
  printf '%s' "${ip}"
}

# 可通过环境变量覆盖：
#   SERVER_ADDR=192.168.31.50 GUIZANGAI_MODEL=qwen2.5:3b ./run-local-guizangai-dashboard.sh
# 默认自动探测本机局域网 IP；探测失败再回退到占位地址。
SERVER_ADDR="${SERVER_ADDR:-$(detect_lan_ip)}"
SERVER_ADDR="${SERVER_ADDR:-192.168.31.193}"
WEB_PORT="${WEB_PORT:-8080}"
GUIZANGAI_MODEL="${GUIZANGAI_MODEL:-qwen2.5:3b}"
GUIZANGAI_HF_REPO="${GUIZANGAI_HF_REPO:-Qwen/Qwen2.5-3B}"
GUIZANGAI_HF_URL="${GUIZANGAI_HF_URL:-https://huggingface.co/${GUIZANGAI_HF_REPO}}"
GUIZANGAI_API_STYLE="${GUIZANGAI_API_STYLE:-ollama}"
GUIZANGAI_BASE_URL="${GUIZANGAI_BASE_URL:-http://host.docker.internal:11434}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://127.0.0.1:11434}"
OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION:-0}"
OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE:-30m}"
AUTO_INSTALL_LOCAL_AGENT="${AUTO_INSTALL_LOCAL_AGENT:-true}"

log() {
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$*"
}

random_hex() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    python3 - <<'PY'
import secrets
print(secrets.token_hex(32))
PY
  fi
}

ensure_env_file() {
  if [ ! -f "${ENV_FILE}" ]; then
    cp "${ENV_EXAMPLE}" "${ENV_FILE}"
    log "已从 .env.example 生成 server/.env"
  fi
}

port_available() {
  python3 - "$1" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
    except OSError:
        sys.exit(1)
PY
}

dashboard_healthy_on_port() {
  curl -fsS --max-time 2 "http://127.0.0.1:$1/health" >/dev/null 2>&1
}

choose_web_port() {
  local start="${WEB_PORT}" port
  for port in $(seq "${start}" "$((start + 20))"); do
    if dashboard_healthy_on_port "${port}"; then
      WEB_PORT="${port}"
      log "检测到仪表盘已在端口 ${WEB_PORT} 运行，继续复用该端口。"
      return
    fi
    if port_available "${port}"; then
      WEB_PORT="${port}"
      if [ "${WEB_PORT}" != "${start}" ]; then
        log "端口 ${start} 被占用，自动改用可用端口 ${WEB_PORT}。"
      fi
      return
    fi
  done
  log "从 ${start} 到 $((start + 20)) 都没有可用端口，请手动设置 WEB_PORT 后重试。"
  exit 1
}

set_env_values() {
  export WEB_PORT GUIZANGAI_BASE_URL GUIZANGAI_API_STYLE GUIZANGAI_MODEL
  export AUTH_SECRET_VALUE="${AUTH_SECRET_VALUE:-$(random_hex)}"
  export AGENT_REG_PASSWORD_VALUE="${AGENT_REG_PASSWORD_VALUE:-$(random_hex | cut -c 1-20)}"

  python3 - "${ENV_FILE}" <<'PY'
import os
import sys
from pathlib import Path

path = Path(sys.argv[1])
updates = {
    "WEB_PORT": os.environ["WEB_PORT"],
    "GUIZANGAI_BASE_URL": os.environ["GUIZANGAI_BASE_URL"],
    "GUIZANGAI_API_STYLE": os.environ["GUIZANGAI_API_STYLE"],
    "GUIZANGAI_MODEL": os.environ["GUIZANGAI_MODEL"],
    "GUIZANGAI_CHAT_PATH": os.environ.get("GUIZANGAI_CHAT_PATH", ""),
    "GUIZANGAI_TIMEOUT_SECONDS": os.environ.get("GUIZANGAI_TIMEOUT_SECONDS", "120"),
    "GUIZANGAI_MAX_NEW_TOKENS": os.environ.get("GUIZANGAI_MAX_NEW_TOKENS", "96"),
    "GUIZANGAI_TEMPERATURE": os.environ.get("GUIZANGAI_TEMPERATURE", "0.2"),
    "GUIZANGAI_SEND_RAW_LOGS": os.environ.get("GUIZANGAI_SEND_RAW_LOGS", "false"),
    "GUIZANGAI_RAW_LOGS_MAX": os.environ.get("GUIZANGAI_RAW_LOGS_MAX", "20"),
    "GUIZANGAI_RAW_LOGS_FIELDS": os.environ.get(
        "GUIZANGAI_RAW_LOGS_FIELDS",
        "timestamp,agent.name,rule.level,rule.description,rule.groups,rule.mitre.id,syscheck.path,syscheck.event,data.srcip,location",
    ),
    "ANALYSIS_INTERVAL_MINUTES": os.environ.get("ANALYSIS_INTERVAL_MINUTES", "0.5"),
    "SUMMARY_WINDOW": os.environ.get("SUMMARY_WINDOW", "now-24h"),
    "AUTH_SECRET": os.environ["AUTH_SECRET_VALUE"],
    "AGENT_REG_PASSWORD": os.environ["AGENT_REG_PASSWORD_VALUE"],
    "DEFAULT_ADMIN_USER": os.environ.get("DEFAULT_ADMIN_USER", "testadmin"),
    "DEFAULT_ADMIN_PASSWORD": os.environ.get("DEFAULT_ADMIN_PASSWORD", "testpass"),
    "CORS_ORIGINS": os.environ.get(
        "CORS_ORIGINS",
        f"http://localhost:{os.environ['WEB_PORT']},http://127.0.0.1:{os.environ['WEB_PORT']}",
    ),
}

lines = path.read_text(encoding="utf-8").splitlines()
existing = {}
for i, line in enumerate(lines):
    if not line or line.lstrip().startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    existing[key] = (i, value)

for key, value in updates.items():
    if key in existing:
        i, old = existing[key]
        # 已有密钥/注册密码时保留，避免每次重跑造成登录令牌或 Agent 注册变化。
        if key in {"AUTH_SECRET", "AGENT_REG_PASSWORD"} and old.strip():
            continue
        lines[i] = f"{key}={value}"
    else:
        lines.append(f"{key}={value}")

path.write_text("\n".join(lines) + "\n", encoding="utf-8")
PY
}

ensure_ollama_guizangai() {
  if ! command -v curl >/dev/null 2>&1; then
    log "未找到 curl，跳过 GuizangAI 健康检查。"
    return
  fi

  if ! command -v ollama >/dev/null 2>&1; then
    if [ "$(uname -s)" = "Darwin" ] && command -v brew >/dev/null 2>&1; then
      log "未检测到 ollama 命令，正在通过 Homebrew 安装 Ollama ..."
      brew install ollama
    else
      log "未找到 ollama 命令，无法自动部署 GGUF 模型；请先安装 Ollama。"
      return
    fi
  fi

  if curl -fsS "${OLLAMA_BASE_URL}/api/tags" >/dev/null 2>&1; then
    log "本地 Ollama/GuizangAI 服务已响应：${OLLAMA_BASE_URL}"
  else
    log "正在启动本地 Ollama 服务（Flash Attention=${OLLAMA_FLASH_ATTENTION}, KeepAlive=${OLLAMA_KEEP_ALIVE}）..."
    OLLAMA_FLASH_ATTENTION="${OLLAMA_FLASH_ATTENTION}" \
      OLLAMA_KEEP_ALIVE="${OLLAMA_KEEP_ALIVE}" \
      nohup ollama serve >"${ROOT_DIR}/ollama.log" 2>&1 &
    for _ in $(seq 1 30); do
      if curl -fsS "${OLLAMA_BASE_URL}/api/tags" >/dev/null 2>&1; then
        break
      fi
      sleep 2
    done
  fi

  if ! curl -fsS "${OLLAMA_BASE_URL}/api/tags" >/dev/null 2>&1; then
    log "GuizangAI 服务暂未响应；部署会继续，但 AI 会在调用失败时回退为 mock。"
    return
  fi

  if ! python3 - "${GUIZANGAI_MODEL}" <<'PY'
import subprocess
import sys

target = sys.argv[1]
out = subprocess.check_output(["ollama", "list"], text=True)
names = [line.split()[0] for line in out.splitlines()[1:] if line.split()]
sys.exit(0 if target in names or f"{target}:latest" in names else 1)
PY
  then
    log "未检测到 GuizangAI 模型 ${GUIZANGAI_MODEL}，正在通过 Ollama 拉取 ..."
    if ! ollama pull "${GUIZANGAI_MODEL}"; then
      log "Ollama 拉取失败。请确认本机网络可访问模型源，或手动准备 GuizangAI 模型。"
      log "请手动准备 GuizangAI 3B 后设置 GUIZANGAI_MODEL / GUIZANGAI_BASE_URL。"
      return
    fi
  else
    log "已检测到 GuizangAI 模型：${GUIZANGAI_MODEL}"
  fi
}

wait_for_dashboard() {
  local url="http://${SERVER_ADDR}:${WEB_PORT}/health"
  log "等待仪表盘健康检查：${url}"
  for _ in $(seq 1 60); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      log "仪表盘已就绪。"
      return 0
    fi
    sleep 5
  done
  log "健康检查超时，请稍后查看：cd ${SERVER_DIR} && docker compose logs -f bff web"
  return 1
}

env_value() {
  python3 - "${ENV_FILE}" "$1" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
target = sys.argv[2]
for line in path.read_text(encoding="utf-8").splitlines():
    if "=" not in line or line.lstrip().startswith("#"):
        continue
    key, value = line.split("=", 1)
    if key == target:
        print(value)
        break
PY
}

local_agent_name() {
  local name
  name="$(scutil --get LocalHostName 2>/dev/null || hostname -s 2>/dev/null || scutil --get ComputerName 2>/dev/null || hostname)"
  name="$(printf '%s' "${name}" | tr ' ' '-' | LC_ALL=C tr -cd 'A-Za-z0-9._-')"
  [ -n "${name}" ] && printf '%s\n' "${name}" || printf 'macos-agent\n'
}

ensure_local_agent() {
  if [ "${AUTO_INSTALL_LOCAL_AGENT}" != "true" ]; then
    log "已跳过本机 Agent 自动接入（AUTO_INSTALL_LOCAL_AGENT=${AUTO_INSTALL_LOCAL_AGENT}）。"
    return
  fi
  if [ "$(uname -s)" != "Darwin" ]; then
    log "当前不是 macOS，跳过本机 Agent 自动安装。"
    return
  fi

  local agent_script="${SERVER_DIR}/agent-dist/install-macos.command"
  local reg_password agent_name conf
  reg_password="$(env_value AGENT_REG_PASSWORD)"
  agent_name="$(local_agent_name)"
  conf="/Library/Ossec/etc/ossec.conf"

  if [ -d "/Library/Ossec" ]; then
    log "检测到本机已安装 Agent，自动更新服务器地址并重启 ..."
    if [ -f "${conf}" ]; then
      sudo /usr/bin/sed -i '' -E "s#<address>[^<]*</address>#<address>${SERVER_ADDR}</address>#" "${conf}" || true
    fi
    sudo /Library/Ossec/bin/wazuh-control restart || sudo /Library/Ossec/bin/wazuh-control start || true
    if sudo /Library/Ossec/bin/wazuh-control status 2>/dev/null | grep -q "is running"; then
      log "本机 Agent 已运行，数据会自动接入仪表盘。"
    else
      log "本机 Agent 重启命令已执行，但状态检查暂未就绪；服务端若显示该设备 Active 则说明已接入。"
    fi
    return
  fi

  if [ ! -f "${agent_script}" ]; then
    log "未找到本机 Agent 安装脚本：${agent_script}，请先检查 deploy.sh 输出。"
    return
  fi

  log "本机还没有 Agent，开始自动安装并注册到 ${SERVER_ADDR} ..."
  chmod +x "${agent_script}"
  sudo bash "${agent_script}" "${SERVER_ADDR}" "${agent_name}" "${reg_password}"
}

trigger_analysis_once() {
  local base="http://${SERVER_ADDR}:${WEB_PORT}"
  local user password payload token
  user="$(env_value DEFAULT_ADMIN_USER)"
  password="$(env_value DEFAULT_ADMIN_PASSWORD)"
  user="${user:-testadmin}"
  password="${password:-testpass}"
  payload="$(python3 - "${user}" "${password}" <<'PY'
import json
import sys

print(json.dumps({"username": sys.argv[1], "password": sys.argv[2]}, ensure_ascii=False))
PY
)"
  token="$(curl -fsS -X POST "${base}/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "${payload}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("token",""))' 2>/dev/null || true)"

  if [ -z "${token}" ]; then
    log "首轮 GuizangAI 分析已由 BFF 启动时自动触发；自动登录失败，跳过额外触发。"
    return
  fi

  log "正在后台触发一轮 GuizangAI 分析，完成后会自动显示在仪表盘 ..."
  (
    curl -fsS -X POST "${base}/api/ai/run" -H "Authorization: Bearer ${token}" >/dev/null \
      && log "GuizangAI 分析完成，结果已写入仪表盘。" \
      || log "GuizangAI 分析触发失败；定时任务会继续自动重试。"
  ) &
}

main() {
  log "准备 Sentinel + 本地 GuizangAI + 仪表盘"
  log "本机局域网 IP（Agent 回连 / 仪表盘访问）：${SERVER_ADDR}"
  log "如不正确可手动指定：SERVER_ADDR=<你的IP> ./run-local-guizangai-dashboard.sh"
  ensure_env_file
  choose_web_port
  set_env_values
  ensure_ollama_guizangai

  log "运行 sentinel-installer 部署脚本，服务地址：${SERVER_ADDR}:${WEB_PORT}"
  chmod +x "${SERVER_DIR}/deploy.sh"
  (cd "${SERVER_DIR}" && ./deploy.sh "${SERVER_ADDR}")

  wait_for_dashboard || true
  ensure_local_agent || true
  trigger_analysis_once || true

  cat <<EOF

==================================================================
完成。

仪表盘地址： http://${SERVER_ADDR}:${WEB_PORT}
Agent 下载页： http://${SERVER_ADDR}:${WEB_PORT}/download/
GuizangAI 接口：${GUIZANGAI_BASE_URL} (${GUIZANGAI_API_STYLE})

默认登录账号在 server/.env 的 DEFAULT_ADMIN_USER / DEFAULT_ADMIN_PASSWORD。
查看后端日志：cd "${SERVER_DIR}" && docker compose logs -f bff
==================================================================
EOF
}

main "$@"
