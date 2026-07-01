<#
.SYNOPSIS
  GuiZang - Windows 安全监控终端一键安装脚本
.DESCRIPTION
  下载并静默安装 GuiZang 监控程序，配置服务器地址，设置开机自启 + 故障自动恢复，启动服务。
  解决"关机后掉线"的问题：服务设为自动(延迟)启动，并配置崩溃后自动重启。
.EXAMPLE
  # 方式一（推荐）：先在下方【每客户改一次】填好服务器IP，技术人员直接零输入运行：
  powershell -ExecutionPolicy Bypass -File .\install-windows.ps1
.EXAMPLE
  # 方式二：临时指定 Manager：
  powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 -Manager 192.168.1.10
.NOTES
  必须以管理员身份运行。
#>
param(
    [string] $Manager = "",                                          # GuiZang 服务器 IP/域名（留空则用下方默认值/自动发现）
    [string] $AgentName = "",                                         # 终端自定义名称（留空将提示输入，回车则用机器名）
    [string] $RegistrationPassword = "",                             # 注册密码（启用注册密码时填）
    [string] $Version = "",                                           # 客户端版本；留空=自动获取 Wazuh 最新版
    [string] $Group = "default"                                       # 终端分组
)

# 版本：留空则自动获取 Wazuh 官方最新版，取不到则回退到已知稳定版。
$FallbackVersion = "4.14.5"
function Resolve-LatestVersion {
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/wazuh/wazuh/releases/latest" `
            -Headers @{ "User-Agent" = "GuiZang-Installer" } -TimeoutSec 8
        $v = ($rel.tag_name -replace '^v', '')
        if ($v -match '^[0-9.]+$') { return $v }
    } catch { }
    return $FallbackVersion
}

# ============================================================
#  【每客户改一次】把这里填成该客户服务器(Manager)的固定 IP，
#   之后所有机器装机零输入。建议给服务器设静态 IP 或用域名。
$DefaultManager = ""     # 例：$DefaultManager = "192.168.1.10"
$DefaultRegPassword = "" # 一般留空：启用了注册密码时，运行时会提示你手动输入（不写进脚本更安全）
$DefaultVersion = ""     # 由 deploy.sh 自动填入服务器(Manager)版本以保持一致；留空=自动取最新
# ============================================================

$ErrorActionPreference = "Stop"
try {
    [Net.ServicePointManager]::SecurityProtocol = `
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
} catch { }

function Invoke-DownloadFile {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][string] $OutFile
    )
    for ($i = 1; $i -le 5; $i++) {
        try {
            Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -TimeoutSec 120
            if ((Test-Path $OutFile) -and ((Get-Item $OutFile).Length -gt 0)) { return }
        } catch {
            if ($i -eq 5) { throw }
            Write-Host "    下载失败，${i}/5，3 秒后重试 ..." -ForegroundColor Yellow
            Start-Sleep -Seconds 3
        }
    }
}

# 自动发现服务器：扫描本机所在网段 1514 端口（通信端口）
function Find-Manager {
    Write-Host "[*] 未指定服务器地址，正在本网段自动搜索 GuiZang 服务器(端口1514) ..." -ForegroundColor Yellow
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike "169.*" -and $_.IPAddress -ne "127.0.0.1" -and $_.PrefixOrigin -ne "WellKnown" } |
        Select-Object -First 1).IPAddress
    if (-not $ip) { return "" }
    $prefix = ($ip -split '\.')[0..2] -join '.'
    $found = @()
    $jobs = 1..254 | ForEach-Object {
        $target = "$prefix.$_"
        $client = New-Object System.Net.Sockets.TcpClient
        $async = $client.BeginConnect($target, 1514, $null, $null)
        [pscustomobject]@{ IP = $target; Client = $client; Async = $async }
    }
    Start-Sleep -Milliseconds 700
    foreach ($j in $jobs) {
        if ($j.Async.IsCompleted -and $j.Client.Connected) { $found += $j.IP }
        $j.Client.Close()
    }
    if ($found.Count -eq 1) { Write-Host "[*] 发现服务器：$($found[0])" -ForegroundColor Green; return $found[0] }
    if ($found.Count -gt 1) { Write-Host "[*] 发现多台候选：$($found -join ', ')" -ForegroundColor Yellow; return $found[0] }
    return ""
}

# 解析 Manager：命令行参数 > 脚本内默认 > 自动发现 > 交互输入
if (-not $Manager) { $Manager = $DefaultManager }
if (-not $Manager) { $Manager = Find-Manager }
if (-not $Manager) { $Manager = Read-Host "请输入 GuiZang 服务器的 IP/域名" }
if (-not $Manager) { Write-Host "[X] 未确定 Manager 地址，退出。" -ForegroundColor Red; exit 1 }

# 注册密码：命令行参数 > 脚本内默认 > 交互输入（通用 exe 在密码服务器上用）
if (-not $RegistrationPassword) { $RegistrationPassword = $DefaultRegPassword }
if (-not $RegistrationPassword) {
    $RegistrationPassword = Read-Host "如有【服务器注册密码】请输入（没设密码就直接回车跳过）"
}

# 终端自定义名称：命令行参数 > 交互输入。多台电脑时便于在仪表盘快速识别（回车默认用机器名）。
if (-not $AgentName) {
    $defaultName = $env:COMPUTERNAME
    $inputName = Read-Host "请输入该终端的【自定义名称】，便于仪表盘识别（仅限字母/数字/中划线，回车默认：$defaultName）"
    if ($inputName) { $AgentName = $inputName } else { $AgentName = $defaultName }
}

# Wazuh 代理名只允许字母数字和 - _ . ；空格转 -，去掉中文等非法字符（否则注册被拒）
$AgentName = ($AgentName -replace '\s', '-' -replace '[^A-Za-z0-9._-]', '')
if (-not $AgentName) { $AgentName = $env:COMPUTERNAME -replace '[^A-Za-z0-9._-]', '' }
if (-not $AgentName) { $AgentName = "win-agent" }

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[X] 请右键『以管理员身份运行 PowerShell』后再执行本脚本。" -ForegroundColor Red
        exit 1
    }
}

Assert-Admin
Write-Host "==== GuiZang · Windows 安全监控终端 安装 ====" -ForegroundColor Cyan
Write-Host "Manager   : $Manager"
Write-Host "AgentName : $AgentName"
Write-Host "Version   : $Version`n"

# 关键路径
$ossecDir   = "${env:ProgramFiles(x86)}\ossec-agent"
$confPath   = Join-Path $ossecDir "ossec.conf"
$clientKeys = Join-Path $ossecDir "client.keys"
$agentAuth  = Join-Path $ossecDir "agent-auth.exe"

# 安装前先记下"旧的服务器地址"，用于判断本次 IP 是否变化（覆盖重装时 MSI 会保留旧配置）
$oldManager = ""
if (Test-Path $confPath) {
    $m = [regex]::Match((Get-Content $confPath -Raw), '<address>(.*?)</address>')
    if ($m.Success) { $oldManager = $m.Groups[1].Value.Trim() }
}

# 1) 下载 MSI（版本优先级：-Version 参数 > 脚本内默认(对齐 Manager) > 自动取最新）
if (-not $Version) { $Version = $DefaultVersion }
if (-not $Version) { $Version = Resolve-LatestVersion }
Write-Host "[*] 安装版本：$Version" -ForegroundColor Yellow
$msiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi"
$msi = Join-Path $env:TEMP "wazuh-agent-$Version.msi"
Write-Host "[1/5] 下载安装包 ..." -ForegroundColor Yellow
Invoke-DownloadFile -Uri $msiUrl -OutFile $msi

# 2) 静默安装（同步等待完成）
Write-Host "[2/5] 安装 Agent ..." -ForegroundColor Yellow
$msiArgs = @(
    "/i", "`"$msi`"", "/q",
    "WAZUH_MANAGER=`"$Manager`"",
    "WAZUH_AGENT_NAME=`"$AgentName`"",
    "WAZUH_AGENT_GROUP=`"$Group`"",
    "WAZUH_REGISTRATION_SERVER=`"$Manager`""
)
if ($RegistrationPassword -ne "") {
    $msiArgs += "WAZUH_REGISTRATION_PASSWORD=`"$RegistrationPassword`""
}
$proc = Start-Process msiexec.exe -ArgumentList $msiArgs -Wait -PassThru
if ($proc.ExitCode -ne 0) {
    Write-Host "[X] 安装失败，msiexec 退出码 $($proc.ExitCode)" -ForegroundColor Red
    exit $proc.ExitCode
}

# 2.5) 兜底：强制把服务器地址改成本次的 IP（覆盖重装时 MSI 会保留旧配置，这里确保切到新 IP）
if (Test-Path $confPath) {
    $conf = Get-Content $confPath -Raw
    $conf = [regex]::Replace($conf, '<address>.*?</address>', "<address>$Manager</address>")
    [System.IO.File]::WriteAllText($confPath, $conf, (New-Object System.Text.UTF8Encoding($false)))
}

# 2.6) 若服务器地址发生变化：清旧密钥并重新注册到新服务器（避免还连旧服务器/旧密钥失效）
if ($oldManager -and ($oldManager -ne $Manager)) {
    Write-Host "[*] 检测到服务器地址变化：$oldManager -> $Manager，正在重新注册 ..." -ForegroundColor Yellow
    Stop-Service WazuhSvc -ErrorAction SilentlyContinue
    if (Test-Path $clientKeys) { Remove-Item $clientKeys -Force -ErrorAction SilentlyContinue }
    if (Test-Path $agentAuth) {
        $authArgs = @("-m", $Manager, "-A", $AgentName)
        if ($RegistrationPassword -ne "") { $authArgs += @("-P", $RegistrationPassword) }
        try { & $agentAuth @authArgs 2>$null } catch { }
    }
    # 若上面注册失败，client.keys 为空时服务启动会按 ossec.conf 的 enrollment 自动注册
}

# 2.7) 部署防火墙状态采集（GuiZang 自定义）：每 30 分钟上报防火墙开关，供仪表盘"设备详情页"展示
Write-Host "[*] 配置防火墙状态采集 ..." -ForegroundColor Yellow
$fwScript = Join-Path $ossecDir "guizang-firewall.ps1"
$fwBody = @'
$ErrorActionPreference='SilentlyContinue'
function st($b){ if($b -eq $true){'on'}else{'off'} }
$p = Get-NetFirewallProfile
$dom = ($p | Where-Object {$_.Name -eq 'Domain'}).Enabled
$pri = ($p | Where-Object {$_.Name -eq 'Private'}).Enabled
$pub = ($p | Where-Object {$_.Name -eq 'Public'}).Enabled
$rt  = (Get-MpComputerStatus).RealTimeProtectionEnabled
$en  = ($dom -eq $true) -or ($pri -eq $true) -or ($pub -eq $true)
"guizang_firewall enabled=$(st $en) domain=$(st $dom) private=$(st $pri) public=$(st $pub) realtime=$(st $rt) platform=windows"
'@
[System.IO.File]::WriteAllText($fwScript, $fwBody, (New-Object System.Text.UTF8Encoding($false)))
if (Test-Path $confPath) {
    if ((Get-Content $confPath -Raw) -notmatch 'guizang-firewall') {
        $fwBlock = @"

<ossec_config>
  <localfile>
    <log_format>full_command</log_format>
    <command>powershell.exe -ExecutionPolicy Bypass -NoProfile -File "$fwScript"</command>
    <alias>guizang-firewall</alias>
    <frequency>1800</frequency>
  </localfile>
</ossec_config>
"@
        Add-Content -Path $confPath -Value $fwBlock -Encoding UTF8
    }
}

# 3) 服务设为开机自启（自动-延迟），保证每次开机都拉起
Write-Host "[3/5] 配置开机自启 ..." -ForegroundColor Yellow
sc.exe config WazuhSvc start= delayed-auto | Out-Null

# 4) 配置故障自动恢复：崩溃后 5s/10s/30s 自动重启，计数器 1 天后重置
Write-Host "[4/5] 配置故障自动恢复 ..." -ForegroundColor Yellow
sc.exe failure WazuhSvc reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null

# 5) 启动服务并校验
Write-Host "[5/5] 启动服务 ..." -ForegroundColor Yellow
Restart-Service WazuhSvc -ErrorAction SilentlyContinue
Start-Service WazuhSvc -ErrorAction SilentlyContinue

# 轮询等待服务就绪（慢机器上启动需要几秒，单次检查易误报"未运行"）
$svc = Get-Service WazuhSvc
for ($i = 0; $i -lt 15 -and $svc.Status -ne "Running"; $i++) {
    Start-Sleep -Seconds 2
    $svc = Get-Service WazuhSvc
}
if ($svc.Status -eq "Running") {
    Write-Host "`n[OK] 安装完成，GuiZang 监控服务正在运行，已设为开机自启。" -ForegroundColor Green
    Write-Host "     日志：C:\Program Files (x86)\ossec-agent\ossec.log"
} else {
    Write-Host "`n[!] 服务未处于运行状态（当前：$($svc.Status)），请检查与 $Manager 的网络连通(1514/1515端口)。" -ForegroundColor Red
}

Remove-Item $msi -ErrorAction SilentlyContinue
