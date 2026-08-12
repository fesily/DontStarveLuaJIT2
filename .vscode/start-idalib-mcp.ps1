# ============================================================================
# idalib-mcp 启动脚本
# 启动 ida-pro-mcp 的 idalib worker HTTP 服务(端口 8745, 与 .omp/mcp.json 一致)
# 用法: powershell -ExecutionPolicy Bypass -File .vscode/start-idalib-mcp.ps1
# 依赖: IDA Professional 9.3 (C:\Program Files\IDA Professional 9.3) + ida-pro-mcp 2.x
# ============================================================================

param(
    [int]$Port = 8745,
    [string]$BindHost = "127.0.0.1",
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

# ---- 定位 python ----
$PythonCandidates = @(
    "C:\Users\fesil\AppData\Local\Microsoft\WindowsApps\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\python.exe",
    (Get-Command python3 -ErrorAction SilentlyContinue).Source,
    (Get-Command python -ErrorAction SilentlyContinue).Source
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

if (-not $PythonCandidates) {
    throw "Python not found. Set python3.exe path."
}
$Python = $PythonCandidates[0]
Write-Host "Python: $Python"

# ---- 定位 idalib_server.py ----
$ServerPath = $null
$PyBase = "C:\Users\fesil\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_qbz5n2kfra8p0\LocalCache\local-packages\Python313\site-packages"
$ServerCandidates = @(
    (Join-Path $PyBase "ida_pro_mcp\idalib_server.py"),
    (& $Python -c "import ida_pro_mcp.idalib_server,os;print(os.path.join(os.path.dirname(ida_pro_mcp.idalib_server.__file__),'idalib_server.py'))" 2>$null)
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

if (-not $ServerCandidates) {
    throw "idalib_server.py not found. Install: pip install git+https://github.com/mrexodia/ida-pro-mcp.git"
}
$ServerPath = $ServerCandidates[0]
Write-Host "Server: $ServerPath"

# ---- IDADIR ----
$IdaDir = $env:IDADIR
if (-not $IdaDir) { $IdaDir = "C:\Program Files\IDA Professional 9.3" }
if (-not (Test-Path $IdaDir)) {
    Write-Warning "IDADIR not found at '$IdaDir' — idalib may fail. Set env IDADIR."
}
$env:IDADIR = $IdaDir

# ---- 清理旧进程(杀进程树, 含 worker 子进程) ----
$old = Get-Process -Name "python*" -ErrorAction SilentlyContinue |
    Where-Object { $_.Path -eq $Python }
foreach ($p in $old) {
    Write-Host "Killing old process: $($p.Id)"
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Milliseconds 500

# ---- 检查端口占用 ----
$inUse = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($inUse) {
    Write-Warning "Port $Port already in use by PID $($inUse.OwningProcess). Reusing existing service."
    exit 0
}

# ---- 后台启动(隐藏窗口) ----
$args = @($ServerPath, "--host", $BindHost, "--port", "$Port")
if ($Verbose) { $args += "--verbose" }
Write-Host "Starting: $Python $($args -join ' ')"

$proc = Start-Process -WindowStyle Hidden -FilePath $Python -ArgumentList $args -PassThru
Write-Host "Started PID: $($proc.Id)"

# ---- 等待就绪(最多 60s) ----
$ready = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 1
    try {
        $r = Invoke-WebRequest -Uri "http://$BindHost`:$Port/mcp" -Method POST `
            -ContentType "application/json" `
            -Body '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' `
            -TimeoutSec 3 -UseBasicParsing
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
}

if ($ready) {
    Write-Host "OK: idalib-mcp ready at http://$BindHost`:$Port/mcp"
} else {
    Write-Host "ERR: timeout waiting for service. Check logs: hub logs idalib-mcp"
    exit 1
}
