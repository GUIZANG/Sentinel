<# Sentinel - Windows Agent 卸载脚本。必须以管理员身份运行。 #>
$ErrorActionPreference = "Continue"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "请以管理员身份运行 PowerShell。"
    }
}

Assert-Admin
Write-Host "==== Sentinel · Windows Agent 卸载 ===="

Stop-Service WazuhSvc -ErrorAction SilentlyContinue
Set-Service WazuhSvc -StartupType Disabled -ErrorAction SilentlyContinue

$products = Get-CimInstance Win32_Product -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -match "Wazuh|OSSEC|GuiZang|Sentinel" }
foreach ($p in $products) {
    Write-Host "[*] 卸载 $($p.Name)"
    $p.Uninstall() | Out-Null
}

Remove-Item "C:\Program Files (x86)\ossec-agent\shared\guizang-firewall.ps1" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files (x86)\ossec-agent\guizang-agent-note.txt" -Force -ErrorAction SilentlyContinue

Write-Host "[OK] 卸载完成。如需彻底清空历史配置，可手动删除 C:\Program Files (x86)\ossec-agent。"
