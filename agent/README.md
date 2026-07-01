# Agent 一键安装

由技术人员现场执行；脚本会自动安装 Wazuh Agent、配置 Manager 地址、设置**开机自启 + 故障自动恢复**，并启动服务。

## 三个脚本的关系（先看这里）

整套系统的安装脚本：

| 脚本 | 在哪运行 | 作用 |
| --- | --- | --- |
| `server/deploy.sh` | **客户服务器**（先跑这个） | 一键装好 Wazuh + 系统，并**自动探测服务器 IP** |
| `agent/install-windows.ps1` | 每台 Windows 电脑 | 装 Windows Agent |
| `agent/install-macos.command` | 每台 Mac 电脑 | 装 Mac Agent |
| `agent/install-linux.sh` | 每台 Linux 主机 | 装 Linux Agent（自动适配 apt/yum/dnf/zypper） |
| `agent/diagnose-*` | 已安装 Agent 的电脑 | 收集服务状态、Manager 地址、端口连通和最近日志 |
| `agent/uninstall-*` | 已安装 Agent 的电脑 | 停止服务并卸载 Agent 主程序 |
| `installers/bootstrap/install-*-ui.*` | 要部署核心系统的电脑 | 打开本地浏览器，可视化展示 Docker、AI 模型、核心服务和本机 Agent 安装进度 |

> **版本自动对齐**：三个脚本都支持自动选择 Wazuh 版本。`deploy.sh` 会把**服务器(Manager)版本**注入到生成的脚本里作为默认版本（Wazuh 要求 Agent 版本 ≤ Manager）；若未注入，则自动获取官方**最新版**。可用 `-Version`（Win）/ `WAZUH_VERSION=`（Mac/Linux）显式覆盖。

**IP 不用你手动找**：跑完 `deploy.sh` 后，它会

1. 用大字打印出 **Agent 该填的 IP**（就是服务器自己的 IP）；
2. 在 `server/agent-dist/` 里**生成两个已经把 IP 填好的 Agent 脚本**。

技术人员只需把 `server/agent-dist/install-windows.ps1` / `install-macos.command`
拷到对应电脑，**直接运行、零输入**。完全不需要自己确认 IP。

> 也就是说：正常流程下你根本不用碰下面的 IP 章节——`deploy.sh` 已经替你填好了。
> 下面的内容是「手动/临时」场景的备用说明。

## 可视化一键安装核心系统

如果是在自己的电脑或服务器上部署整套核心系统，优先使用可视化安装器：

```bash
# macOS
./installers/bootstrap/install-macos-ui.command

# Linux
sudo bash installers/bootstrap/install-linux-ui.sh
```

```powershell
# Windows（需要 WSL）
powershell -ExecutionPolicy Bypass -File .\installers\bootstrap\install-windows-ui.ps1
```

启动器会打开 `http://127.0.0.1:8765`，显示 Docker、Ollama/AI 模型、Compose 服务、健康检查和本机 Agent 接入进度。无浏览器或缺少 Python/WSL 时，回退使用 `server/deploy.sh` 的命令行安装方式。

## 关于「Manager IP 怎么填」（备用：手动场景）

- **同一家客户的所有电脑(50 台)填的是同一个 IP**——就是那台 Wazuh 服务器的 IP；
- Agent **自己**的 IP 不用填，Wazuh 会自动识别；
- 所以你只需要把那一个服务器 IP「确定一次」，脚本提供三种方式，按推荐顺序：

| 方式 | 做法 | 适用 |
| --- | --- | --- |
| ① 预置默认（推荐） | 装机前在脚本顶部 `DefaultManager` / `DEFAULT_MANAGER` 里把服务器 IP 填一次，分发这份脚本 | 技术人员装机**零输入** |
| ② 自动发现 | 不填也不传参，脚本自动扫描本网段 1514 端口找到服务器 | 服务器与电脑同网段时 |
| ③ 命令行/交互 | 运行时用 `-Manager` 传，或脚本弹出提示手动输入 | 临时/调试 |

> 强烈建议：给客户服务器设**静态 IP**（或内网域名如 `wazuh.company.local`），然后用方式①填一次，
> 以后服务器 IP 不会变，所有装机都不用再想 IP 的事。

解析优先级：命令行参数 > 脚本内默认值 > 自动发现 > 交互输入。

## Windows

以**管理员身份**打开 PowerShell（已在脚本顶部填好默认 IP 时，零输入即可）：

```powershell
# 已预置默认 IP：直接运行
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1

# 或临时指定：
powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Manager 192.168.1.10
```

可选参数：

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `-Manager` | Wazuh Manager 的 IP/域名（必填） | — |
| `-AgentName` | Agent 名称 | 机器名 |
| `-RegistrationPassword` | 注册密码（开启 authd 密码时填） | 空 |
| `-Version` | Wazuh 版本 | 自动（对齐 Manager / 最新） |
| `-Group` | Agent 分组 | default |

> 已用 `sc.exe config ... start= delayed-auto` 设为开机自启，并配置崩溃后自动重启——
> 解决"关机/重启后 Agent 掉线"的问题。

## macOS

```bash
# 已预置默认 IP：直接运行
sudo ./install-macos.command

# 或临时指定：
sudo ./install-macos.command 192.168.1.10
```

或直接双击 `install-macos.command`（会弹窗申请管理员权限；未预置 IP 时自动发现，找不到再询问）。

## Linux

自动识别发行版的包管理器（apt / yum / dnf / zypper），从 Wazuh 官方仓库安装。

```bash
# 已预置默认 IP：直接运行
sudo bash install-linux.sh

# 或临时指定：
sudo bash install-linux.sh 192.168.1.10

# 显式指定版本（可选）：
sudo WAZUH_VERSION=4.14.5 bash install-linux.sh
```

## 验证

- Windows：`Get-Service WazuhSvc`，日志 `C:\Program Files (x86)\ossec-agent\ossec.log`
- macOS：`sudo /Library/Ossec/bin/wazuh-control status`，日志 `/Library/Ossec/logs/ossec.log`
- Linux：`sudo /var/ossec/bin/wazuh-control status`，日志 `/var/ossec/logs/ossec.log`
- 服务端：仪表盘「资产」页或 Wazuh 中应能看到该设备上线（active）。仪表盘需登录，默认账号密码均为 `testadmin` / `testpass`（登录后请在右上角「修改账号密码」）。

## 诊断

如果设备装好后不上线，优先运行对应诊断脚本：

```powershell
powershell -ExecutionPolicy Bypass -File .\diagnose-windows.ps1
```

```bash
sudo ./diagnose-macos.command
sudo bash diagnose-linux.sh
```

诊断脚本会输出系统信息、Wazuh 服务状态、Manager 地址、`1514/1515` 端口连通性和最近日志。也可以手动传 Manager 地址，例如 `sudo bash diagnose-linux.sh 192.168.1.10`。

## 卸载

```powershell
powershell -ExecutionPolicy Bypass -File .\uninstall-windows.ps1
```

```bash
sudo ./uninstall-macos.command
sudo bash uninstall-linux.sh
```

卸载脚本会停止服务并移除 Agent 主程序。若需要彻底清空历史配置，可按脚本结束提示手动删除残留目录。

## 完整性校验

`server/deploy.sh` 会在 `server/agent-dist/SHA256SUMS` 生成下载文件的 SHA256 校验值。正式交付时，建议安装前核对脚本或安装包哈希。

## 批量部署（50 台）

- Windows 域环境：用组策略(GPO)/SCCM 下发上面的 PowerShell 命令。
- macOS 车队：用 MDM(Jamf 等)推送 `install-macos.command`。
- 无统一管理工具时：U 盘/共享目录拷贝脚本，技术人员逐台执行（每台 1-2 分钟）。
