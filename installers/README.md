# 原生安装包构建（.exe / .pkg，双击安装）

给员工电脑用的"双击安装"原生安装包。**通用包**：不绑定某个客户的 IP，
安装时自动发现局域网里的服务器，找不到再弹窗让安装人员输入一次 IP（含可选注册密码）。

## 可视化核心系统安装器

`installers/bootstrap/` 里提供三平台可视化安装启动器：

- `install-macos-ui.command`
- `install-linux-ui.sh`
- `install-windows-ui.ps1`

它们用于部署整套核心系统，会启动本地进度页并调用 `server/deploy.sh`。Windows 版本需要 WSL；如果只是给 Windows 终端安装 Agent，请使用 `agent/install-windows.ps1` 或构建后的 `GuiZangAgent.exe`。

> 构建是一次性的（除非升级 Wazuh 版本）。构建好的包放在 `installers/dist/`，
> 之后 `server/deploy.sh` 会自动把它们一并放进下载页。

## macOS（.pkg）—— 在一台 Mac 上构建

```bash
cd installers/macos
./build-pkg.sh
# 产物：installers/dist/GuiZangAgent-macos-arm64.pkg（Apple 芯片）
#       installers/dist/GuiZangAgent-macos-intel64.pkg（Intel 芯片）
```

原理：下载官方 Wazuh Agent pkg，在其 postinstall 末尾追加"设置 Manager + 启动"逻辑后重打包。
安装时无需联网、无嵌套安装。

## Windows（.exe）—— 在一台 Windows 上构建

```powershell
cd installers\windows
powershell -ExecutionPolicy Bypass -File .\build-exe.ps1
# 产物：installers\dist\GuiZangAgent.exe
```

原理：用 ps2exe 把 `agent/install-windows.ps1` 编译成带管理员清单的 exe（双击自动弹 UAC）。

> 把 Windows 上生成的 `GuiZangAgent.exe` 拷回到服务器的 `installers/dist/` 目录，
> 再（重新）跑 `server/deploy.sh`，下载页就会出现 Windows 的 .exe 下载按钮。

## 安装时的 IP 来源（通用包）

1. 自动扫描本网段 `1514` 端口找到服务器；
2. 找不到 → 弹窗让安装人员输入服务器 IP/域名；
3. 同时可输入注册密码（没有则留空）。

> 云服务器（无法局域网发现）场景：安装人员在弹窗里输入公网 IP/域名即可。

## 未签名说明

均为未签名安装包（按你的要求不做付费签名）：
- macOS：双击被拦截时右键 → 打开，或系统设置 → 隐私与安全性 → 仍要打开；
- Windows：SmartScreen 提示时点"更多信息 → 仍要运行"。

## 个人项目版交付建议

- 每次升级 Wazuh Manager 版本后，重新构建 macOS `.pkg` 和 Windows `.exe`，再运行 `server/deploy.sh` 发布到下载页。
- 下载页会同时发布 `SHA256SUMS`，正式交付时建议核对安装包哈希。
- 如果面向非技术用户分发，优先使用双击包；如果被系统安全策略拦截，改用命令行安装脚本。
- 企业级分发需要另行准备 Apple Developer ID、Windows 代码签名证书，以及 macOS MDM/PPPC 权限描述文件；这些不包含在个人项目版内。
