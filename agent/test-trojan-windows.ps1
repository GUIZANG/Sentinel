<#
  GuiZang 安全平台 —— 高危等级「测试木马」(无害，可随时清除)
  =====================================================================
  原理：向受实时监控的目录 C:\GuiZang-Sentinel-Test 投放一个无害标记文件。
        该目录已开启实时文件完整性监控(FIM)，新增文件会命中自定义高危规则，
        在仪表盘「安全告警」中以高危(置顶标红)出现；删除该文件即触发「已清除」，
        约 1~2 分钟后该告警自动转入「已修复」并生成完整时间轴。

  重要：本文件不含任何恶意代码，只是一个文本文件，删除即彻底清除，绝不损坏系统。

  用法（在被监控的 Windows 终端上，用【管理员】PowerShell 运行）：
    投放木马（触发高危告警）:
      powershell -ExecutionPolicy Bypass -File .\test-trojan-windows.ps1
    清除木马（转入「已修复」）:
      powershell -ExecutionPolicy Bypass -File .\test-trojan-windows.ps1 -Clean
#>
param([switch]$Clean)

$ErrorActionPreference = "Stop"
$dir  = "C:\GuiZang-Sentinel-Test"
$file = Join-Path $dir "guizang_test_trojan.txt"

function Restart-WazuhAgent {
    try {
        Restart-Service WazuhSvc -ErrorAction Stop
        Write-Host "    已重启监控服务以加载监控目录配置。" -ForegroundColor DarkGray
        Start-Sleep -Seconds 18
    } catch {
        Write-Host "    [提示] 未能自动重启监控服务（需管理员权限）。请用『管理员』PowerShell 运行本脚本。" -ForegroundColor Yellow
    }
}

if ($Clean) {
    Write-Host "=== 清除测试木马 ===" -ForegroundColor Cyan
    if (Test-Path $file) {
        Remove-Item $file -Force
        Write-Host "[OK] 已删除：$file" -ForegroundColor Green
        Write-Host "     约 1~2 分钟后，该告警将自动转入仪表盘的「已修复」列表（含完整时间轴）。" -ForegroundColor Green
    } else {
        Write-Host "[i] 未发现测试文件，无需清除：$file" -ForegroundColor Yellow
    }
    exit 0
}

Write-Host "=== 投放测试木马（无害） ===" -ForegroundColor Cyan

# 1) 清掉上次残留文件，保证这次是一次干净的「新增文件」事件
if (Test-Path $file) { Remove-Item $file -Force -ErrorAction SilentlyContinue }
# 2) 确保受监控目录存在
New-Item -ItemType Directory -Force -Path $dir -ErrorAction SilentlyContinue | Out-Null
# 3) 重启监控服务：强制拉取最新下发配置并对该目录挂载实时 FIM（等待其就绪）
Write-Host "    正在让监控服务加载实时监控配置，请稍候约 20 秒 ..." -ForegroundColor DarkGray
Restart-WazuhAgent
# 4) 此时实时 FIM 已在监控该目录，再投放文件 → 触发「新增文件」高危告警
$content = @"
[GuiZang 高危测试样本 - 无害]
生成时间: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
说明: 本文件仅用于触发文件完整性(FIM)高危告警演示，不包含任何可执行/恶意代码。
清除: 删除本文件，或运行  test-trojan-windows.ps1 -Clean
"@
Set-Content -Path $file -Value $content -Encoding UTF8

Write-Host "[OK] 已投放：$file" -ForegroundColor Green
Write-Host ""
Write-Host "请到仪表盘『安全告警 -> 告警明细』查看：" -ForegroundColor White
Write-Host "  - 约 30~90 秒后出现一条【高危】告警，已自动置顶并标红；" -ForegroundColor Gray
Write-Host "  - 点『详情』可看到受影响文件、触发时间与 AI 危害分析、以及处置时间轴；" -ForegroundColor Gray
Write-Host "  - 完成演示后运行『 -Clean 』删除文件，该告警会转入『已修复』列表。" -ForegroundColor Gray
