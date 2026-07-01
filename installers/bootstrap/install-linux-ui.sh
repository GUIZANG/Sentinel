#!/bin/bash
# Sentinel - Linux 可视化一键安装启动器
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_DIR="${ROOT_DIR}/server"
UI_SERVER="${ROOT_DIR}/installer-ui/installer_server.py"
PORT="${SENTINEL_INSTALLER_PORT:-8765}"
ADDR="${1:-}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[X] 未找到 python3，无法启动可视化安装页。请改用：cd server && ./deploy.sh"
  exit 1
fi

if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://127.0.0.1:${PORT}" >/dev/null 2>&1 || true
fi

cd "${SERVER_DIR}"
python3 "${UI_SERVER}" --port "${PORT}" --cwd "${SERVER_DIR}" -- ./deploy.sh ${ADDR:+"$ADDR"}
