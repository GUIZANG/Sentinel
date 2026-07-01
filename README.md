# Sentinel 个人安全驾驶舱

Sentinel 是一个可本地落地的终端安全监控个人项目：用 Wazuh 采集终端资产、告警、漏洞与合规数据，用自带 Web 仪表盘展示态势，并可接入本地 AI 生成安全研判和处置建议。

## 功能亮点

- 终端资产、告警、漏洞、端口、软件和合规基线统一展示。
- 支持 Windows、macOS、Linux Agent 一键安装。
- 支持本地可视化一键安装：启动器会打开浏览器展示 Docker、AI 模型、核心服务和 Agent 的安装进度。
- 支持本地 AI 分析、告警归并、Runbook 建议和报告导出。
- 默认收敛数据库、Indexer、Wazuh API 到本机回环地址，降低公网误暴露风险。
- 前端区分演示模式和生产模式：生产构建不会在接口失败时静默显示 mock 数据。

## 快速启动

推荐使用可视化安装器：

```bash
# macOS
./installers/bootstrap/install-macos-ui.command

# Linux
sudo bash installers/bootstrap/install-linux-ui.sh
```

Windows 版可视化安装器位于：

```powershell
powershell -ExecutionPolicy Bypass -File .\installers\bootstrap\install-windows-ui.ps1
```

> Windows 部署核心服务需要 WSL 执行 Linux 版部署脚本；如果只给 Windows 终端安装 Agent，请使用 `/download/` 中的 Windows Agent 安装脚本。

命令行安装方式：

```bash
cd server
chmod +x deploy.sh
./deploy.sh
```

`server/deploy.sh` 是命令行一键安装的唯一入口：会自动准备 Docker、Ollama/AI 模型、核心服务、Agent 下载页，并在本机可用时接入当前设备。若 `8080` 被占用，会自动尝试后续端口并写回 `server/.env`。

部署脚本会优先接入 GuizangAI：如果存在已解压的 `models/guizangAI/` 或项目根目录的 `guizangAI.gz`，会注册为 Ollama 模型 `guizangai-soc100-1.5b:q4`；压缩包解压成功后会自动删除。没有本地模型包时才回退到公开模型。

云服务器请显式传公网 IP 或域名：

```bash
./deploy.sh <公网IP或域名>
```

启动完成后访问：

- 仪表盘：`http://<服务器IP>:8080`
- Agent 下载页：`http://<服务器IP>:8080/download/`

默认登录账号来自 `server/.env`：

```text
DEFAULT_ADMIN_USER=testadmin
DEFAULT_ADMIN_PASSWORD=testpass
```

首次登录后请在右上角修改账号密码。

## 安全默认值

- `5432`、`9200`、`55000` 默认只绑定 `127.0.0.1`，不要直接开放到公网。
- `1514/1515` 用于 Agent 通信与注册；公网部署时必须妥善保存 `AGENT_REG_PASSWORD`。
- `AUTH_SECRET` 留空时由部署脚本自动生成。
- `CORS_ORIGINS` 生产环境应改为实际访问域名。

## 演示模式

前端开发环境默认允许 mock 数据，方便快速预览。生产构建默认关闭 mock 回退。如果需要演示，可在 `frontend/.env` 中设置：

```text
VITE_DEMO_MODE=1
```

## 项目结构

```text
server/       Docker Compose、一键部署、下载页生成
bff/          FastAPI 后端、鉴权、Wazuh 聚合、AI 调度
frontend/     React 仪表盘
agent/        三平台安装、诊断、卸载脚本
installers/   macOS pkg / Windows exe 构建脚本
installer-ui/ 本地可视化安装页与进度服务
ai-finetune/  AI 数据与微调工作区
```

旧的 `remote-server-code/` 交付副本已清理；当前以上目录为权威项目结构。

## Agent 交付

部署脚本会生成 `server/agent-dist/` 并通过 `/download/` 发布：

- `install-*`：安装脚本
- `diagnose-*`：一键诊断脚本
- `uninstall-*`：卸载脚本
- `SHA256SUMS`：下载完整性校验

更详细说明见 `agent/README.md` 和 `installers/README.md`。

## 个人项目版说明

当前版本适合作为个人项目、内网演示或小规模自托管安全驾驶舱。它不包含企业级代码签名、MDM/PPPC 授权配置、商业证书和合规认证。正式公网部署前，请至少配置 HTTPS、强密码、安全组和备份策略。
