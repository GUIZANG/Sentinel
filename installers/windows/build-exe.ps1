<#
.SYNOPSIS
  在【Windows】上把 Agent 安装脚本编译成双击运行的 .exe。
.DESCRIPTION
  使用 ps2exe 把 agent/install-windows.ps1 编译为 GuiZangAgent.exe，
  带管理员清单(双击自动弹 UAC 提权)。exe 运行时会自动发现服务器，
  找不到则提示输入 IP（沿用脚本里的逻辑）。
.NOTES
  在 Windows 上用 PowerShell 运行本脚本即可：
    powershell -ExecutionPolicy Bypass -File .\build-exe.ps1
#>
$ErrorActionPreference = "Stop"

# 1) 确保 ps2exe 已安装
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "[*] 安装 ps2exe 模块 ..." -ForegroundColor Yellow
    Install-Module -Name ps2exe -Scope CurrentUser -Force -AllowClobber
}
Import-Module ps2exe

# 2) 路径
$here   = Split-Path -Parent $MyInvocation.MyCommand.Path
$src    = Join-Path $here "..\..\agent\install-windows.ps1"
$distDir= Join-Path $here "..\dist"
if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir | Out-Null }
$out    = Join-Path $distDir "GuiZangAgent.exe"

if (-not (Test-Path $src)) { throw "找不到源脚本：$src" }

# 3) 编译（-requireAdmin 让双击 exe 自动请求管理员；保留控制台以便输入 IP）
Write-Host "[*] 编译 $out ..." -ForegroundColor Yellow
Invoke-PS2EXE -InputFile $src -OutputFile $out `
    -requireAdmin `
    -title "GuiZang 安全监控终端 安装" `
    -product "GuiZang 安全监控终端" `
    -company "GuiZang" `
    -description "GuiZang 企业终端安全监控安装程序"

Write-Host "`n[OK] 完成：$out" -ForegroundColor Green
Write-Host "    双击即可安装（会弹 UAC 请求管理员）。未签名时 SmartScreen 可能拦截，点『更多信息→仍要运行』。"
