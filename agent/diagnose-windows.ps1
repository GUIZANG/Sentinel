<# Sentinel - Windows Agent 一键诊断。普通 PowerShell 可运行，部分信息需要管理员权限。 #>
$ErrorActionPreference = "Continue"

$conf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$log = "C:\Program Files (x86)\ossec-agent\ossec.log"
$manager = $args[0]

Write-Host "==== Sentinel · Windows Agent 诊断 ===="
Write-Host "[系统] $((Get-CimInstance Win32_OperatingSystem).Caption) $((Get-CimInstance Win32_OperatingSystem).Version)"
Write-Host "[服务]"
Get-Service WazuhSvc -ErrorAction SilentlyContinue | Format-List Name,Status,StartType

if (Test-Path $conf) {
    $xml = Get-Content $conf -Raw
    if (-not $manager -and $xml -match "<address>([^<]+)</address>") { $manager = $Matches[1] }
    Write-Host "[Manager] $manager"
} else {
    Write-Host "[配置] 未找到 $conf"
}

if ($manager) {
    Write-Host "[端口连通]"
    foreach ($port in 1514,1515) {
        $ok = Test-NetConnection -ComputerName $manager -Port $port -InformationLevel Quiet
        if ($ok) { Write-Host "  $port OK" } else { Write-Host "  $port FAIL" }
    }
}

Write-Host "[最近日志]"
if (Test-Path $log) {
    Get-Content $log -Tail 80
} else {
    Write-Host "未找到 $log"
}
