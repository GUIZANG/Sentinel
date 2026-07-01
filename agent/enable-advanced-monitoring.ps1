<#
  GuiZang 安全平台 —— 高级威胁监控一键开启（Windows）
  =====================================================================
  作用：
    1) 安装微软官方 Sysmon（进程/命令行/注入/网络/注册表行为采集），并写入精简配置；
    2) 重启监控 Agent，使其拉取最新下发配置（扩展的实时 FIM + 事件通道）。
  之后即可检测：木马投放、可疑进程从临时/下载目录启动、编码型 PowerShell、
  流氓软件/弹窗广告的落地与持久化等真实行为。

  说明：Sysmon 是微软 Sysinternals 官方工具，安全、可随时卸载（Sysmon64.exe -u）。
        全程不修改业务数据，对系统无破坏。

  用法（管理员 PowerShell）：
    powershell -ExecutionPolicy Bypass -File .\enable-advanced-monitoring.ps1
  卸载 Sysmon（如需还原）：
    powershell -ExecutionPolicy Bypass -File .\enable-advanced-monitoring.ps1 -Uninstall
#>
param([switch]$Uninstall)

$ErrorActionPreference = "Stop"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch {}

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[X] 请用【管理员】身份的 PowerShell 运行本脚本。" -ForegroundColor Red
    exit 1
  }
}
Assert-Admin

# 按 CPU 架构选择正确的 Sysmon 二进制（ARM64 必须用 Sysmon64a.exe，否则驱动加载失败、服务 Stopped）
function Get-SysmonBinName {
  $arch = ""
  try { $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() } catch {}
  if (-not $arch) { $arch = "$env:PROCESSOR_ARCHITEW6432 $env:PROCESSOR_ARCHITECTURE" }
  if ($arch -match 'Arm64|ARM64') { return "Sysmon64a.exe" }
  if ([Environment]::Is64BitOperatingSystem) { return "Sysmon64.exe" }
  return "Sysmon.exe"
}
$sysmonBin = Get-SysmonBinName
$sysmonExe = Join-Path $env:TEMP $sysmonBin
$cfgPath   = Join-Path $env:TEMP "guizang-sysmon.xml"

function Get-SysmonInstalled {
  return [bool]((Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue))
}

if ($Uninstall) {
  Write-Host "=== 卸载 Sysmon ===" -ForegroundColor Cyan
  if (Get-SysmonInstalled) {
    if (-not (Test-Path $sysmonExe)) { try { Invoke-WebRequest "https://live.sysinternals.com/$sysmonBin" -OutFile $sysmonExe } catch {} }
    $ErrorActionPreference = "Continue"
    if (Test-Path $sysmonExe) { & $sysmonExe -u force 2>&1 | Out-Null }
    Write-Host "[OK] 已卸载 Sysmon。" -ForegroundColor Green
  } else {
    Write-Host "[i] 未检测到 Sysmon，无需卸载。" -ForegroundColor Yellow
  }
  Restart-Service WazuhSvc -ErrorAction SilentlyContinue
  exit 0
}

Write-Host "=== 开启高级威胁监控 ===" -ForegroundColor Cyan

# 1) 写入 Sysmon 精简配置（聚焦进程/落地/持久化/注入/可疑外联）
$cfg = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation>false</CheckRevocation>
  <EventFiltering>
    <ProcessCreate onmatch="exclude"></ProcessCreate>
    <FileCreate onmatch="include">
      <TargetFilename condition="end with">.exe</TargetFilename>
      <TargetFilename condition="end with">.dll</TargetFilename>
      <TargetFilename condition="end with">.ps1</TargetFilename>
      <TargetFilename condition="end with">.bat</TargetFilename>
      <TargetFilename condition="end with">.cmd</TargetFilename>
      <TargetFilename condition="end with">.scr</TargetFilename>
      <TargetFilename condition="end with">.vbs</TargetFilename>
      <TargetFilename condition="end with">.js</TargetFilename>
      <TargetFilename condition="end with">.lnk</TargetFilename>
    </FileCreate>
    <RegistryEvent onmatch="include">
      <TargetObject condition="contains">\CurrentVersion\Run</TargetObject>
      <TargetObject condition="contains">\CurrentVersion\RunOnce</TargetObject>
    </RegistryEvent>
    <CreateRemoteThread onmatch="exclude"></CreateRemoteThread>
    <NetworkConnect onmatch="include">
      <Image condition="contains">\Temp\</Image>
      <Image condition="contains">\Downloads\</Image>
      <Image condition="contains">\AppData\</Image>
      <Image condition="image">powershell.exe</Image>
      <Image condition="image">cmd.exe</Image>
      <Image condition="image">wscript.exe</Image>
      <Image condition="image">cscript.exe</Image>
      <Image condition="image">mshta.exe</Image>
    </NetworkConnect>
  </EventFiltering>
</Sysmon>
'@
Set-Content -Path $cfgPath -Value $cfg -Encoding UTF8
Write-Host "[1/3] 已写入 Sysmon 配置：$cfgPath" -ForegroundColor Yellow

# 2) 下载并安装 Sysmon（按架构选择二进制：ARM64 → Sysmon64a.exe）
Write-Host "[2/3] 安装 Sysmon（架构：$sysmonBin）..." -ForegroundColor Yellow
# 始终重新下载正确架构的二进制，避免上次装错架构的残留
$ok = $false
try { Invoke-WebRequest "https://live.sysinternals.com/$sysmonBin" -OutFile $sysmonExe -UseBasicParsing; $ok = $true } catch {}
if (-not $ok) {
  try {
    $zip = Join-Path $env:TEMP "Sysmon.zip"
    Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zip -UseBasicParsing
    Expand-Archive -Path $zip -DestinationPath (Join-Path $env:TEMP "SysmonPkg") -Force
    Copy-Item (Join-Path $env:TEMP "SysmonPkg\$sysmonBin") $sysmonExe -Force
    $ok = $true
  } catch {}
}
if (-not $ok) {
  Write-Host "[X] 无法下载 Sysmon（该机器可能无法访问微软官网）。" -ForegroundColor Red
  Write-Host "    请手动下载 https://learn.microsoft.com/sysinternals/downloads/sysmon 后，" -ForegroundColor Red
  Write-Host "    运行：$sysmonBin -accepteula -i `"$cfgPath`"，再重启 WazuhSvc 服务。" -ForegroundColor Red
  exit 1
}

# 调用 Sysmon 原生命令时放宽错误处理：Sysmon 会把横幅写到 stderr，Stop 模式会误判为致命错误
$ErrorActionPreference = "Continue"

# 若已安装（可能是错误架构），先卸载，再用正确架构全新安装
if (Get-SysmonInstalled) {
  Write-Host "    检测到已安装 Sysmon，先卸载旧版本（修复架构不匹配）..." -ForegroundColor DarkGray
  & $sysmonExe -u force 2>&1 | Out-Null
  Start-Sleep -Seconds 2
}
& $sysmonExe -accepteula -i $cfgPath 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
Write-Host "    Sysmon 安装完成。" -ForegroundColor DarkGray

# 确保 Sysmon 服务为自启并真正运行
$svcName = (Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1).Name
if ($svcName) {
  Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
  Start-Service -Name $svcName -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 3
  $st = (Get-Service -Name $svcName).Status
  if ($st -ne "Running") {
    # 再尝试启动驱动+服务
    cmd /c "sc start SysmonDrv" 2>&1 | Out-Null
    Start-Service -Name $svcName -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $st = (Get-Service -Name $svcName).Status
  }
  Write-Host "    Sysmon 服务状态：$st" -ForegroundColor DarkGray
  if ($st -ne "Running") {
    Write-Host "    [提示] Sysmon 未启动（ARM 虚拟机常见，驱动加载受限）。已自动改用下方无驱动方案，进程行为检测仍可用。" -ForegroundColor Yellow
  }
} else {
  Write-Host "    [提示] 未检测到 Sysmon 服务，改用下方无驱动方案。" -ForegroundColor Yellow
}

# 2.5) 开启「无驱动」进程/命令行/PowerShell 行为审计（不依赖 Sysmon，ARM/VM 也可用）
Write-Host "[*] 开启进程命令行 + PowerShell 行为审计（无需驱动）..." -ForegroundColor Yellow
$ErrorActionPreference = "Continue"
# PowerShell 脚本块日志（事件 4104）
$sbl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $sbl -Force | Out-Null
Set-ItemProperty -Path $sbl -Name EnableScriptBlockLogging -Value 1 -Type DWord
# 进程创建事件包含命令行（事件 4688 带 CommandLine）
$audit = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
New-Item -Path $audit -Force | Out-Null
Set-ItemProperty -Path $audit -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
# 开启「进程创建」成功审计（用 GUID，避免中文系统子类别名不匹配）
cmd /c 'auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable' 2>&1 | Out-Null
$ErrorActionPreference = "Stop"
Write-Host "    已开启：进程创建命令行审计(4688) + PowerShell 脚本块日志(4104)。" -ForegroundColor DarkGray

# 3) 重启监控 Agent，拉取最新下发配置（实时 FIM 扩展 + 事件通道）
Write-Host "[3/3] 重启监控服务以加载最新配置 ..." -ForegroundColor Yellow
try { Restart-Service WazuhSvc -ErrorAction Stop; Start-Sleep -Seconds 8 } catch {
  Write-Host "    [提示] 未能重启 WazuhSvc（请确认 Agent 已安装）。" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[OK] 高级威胁监控已开启。现在可检测：" -ForegroundColor Green
Write-Host "     - 木马/流氓软件在 Temp/下载/AppData/启动项 的落地（实时 FIM，无需驱动）" -ForegroundColor Gray
Write-Host "     - 从临时/下载目录启动的可疑进程（Security 4688，无需驱动）" -ForegroundColor Gray
Write-Host "     - 编码型/隐藏/远程下载的恶意 PowerShell（脚本块日志 4104，无需驱动）" -ForegroundColor Gray
Write-Host "     - 注册表 Run 键持久化、Windows Defender 检测事件" -ForegroundColor Gray
Write-Host "     注：Sysmon 若在本机可用会额外增强；不可用时以上能力已足够覆盖。" -ForegroundColor DarkGray
