<# Sentinel - Windows 可视化一键安装启动器

核心服务部署仍复用 Linux/macOS 的 server/deploy.sh。Windows 上优先通过 WSL 执行；
如果缺少 Python 或 WSL，会给出明确提示并退出。
#>
param(
    [string] $ServerAddress = "",
    [int] $Port = 8765
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RootDir = Resolve-Path (Join-Path $ScriptDir "..\..")
$UiServer = Join-Path $RootDir "installer-ui\installer_server.py"

function Find-Python {
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) { return @("py", "-3") }
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) { return @("python") }
    return $null
}

function Convert-ToWslPath([string] $Path) {
    $converted = (& wsl wslpath -a "$Path" 2>$null)
    if (-not $converted) { throw "无法转换 WSL 路径：$Path" }
    return $converted.Trim()
}

$python = Find-Python
if (-not $python) {
    Write-Host "[X] 未找到 Python。请先安装 Python 3，或在 macOS/Linux 上运行可视化安装器。" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
    Write-Host "[X] 未找到 WSL。Windows 可视化部署核心服务需要 WSL 执行 server/deploy.sh。" -ForegroundColor Red
    Write-Host "    可先执行：wsl --install，然后重启电脑后再运行本脚本。"
    exit 1
}

$rootWsl = Convert-ToWslPath "$RootDir"
$serverWsl = "$rootWsl/server"
$deployCmd = "cd '$serverWsl' && ./deploy.sh"
if ($ServerAddress) { $deployCmd = "$deployCmd '$ServerAddress'" }

Start-Process "http://127.0.0.1:$Port" | Out-Null
$pythonExe = $python[0]
$pythonArgs = @()
if ($python.Count -gt 1) { $pythonArgs = $python[1..($python.Count - 1)] }
& $pythonExe @pythonArgs "$UiServer" --port "$Port" --cwd "$RootDir" -- wsl bash -lc "$deployCmd"
