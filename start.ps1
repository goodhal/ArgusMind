$ErrorActionPreference = "Continue"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendPort = 6066
$FrontendPort = 8000

function Stop-ProcessOnPort($Port, $Name) {
    Write-Host "[$Name] Checking port $Port..."
    $conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($conn) {
        $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            Write-Host "[$Name] Stopping process $($proc.ProcessName) (PID: $($proc.Id))"
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
    }
}

Write-Host "Checking and stopping existing services..."
Stop-ProcessOnPort -Port $BackendPort -Name "Backend"
Stop-ProcessOnPort -Port $FrontendPort -Name "Frontend"

Write-Host "Checking Python environment..."
$VenvPath = Join-Path $ProjectRoot ".venv"
$Python = Join-Path $VenvPath "Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Host "Virtual environment not found, using system Python"
    $Python = "python"
}

Write-Host "Starting backend service in background..."
$BackendArgs = @("-m", "uvicorn", "src.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "$BackendPort", "--reload")
$BackendProcess = Start-Process -FilePath $Python -ArgumentList $BackendArgs -PassThru -WorkingDirectory $ProjectRoot
Write-Host "Backend process started (PID: $($BackendProcess.Id))"

Write-Host "Waiting for backend to be ready..."
$backendReady = $false
for ($i = 1; $i -le 30; $i++) {
    Start-Sleep -Seconds 1
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:${BackendPort}/api/health" -UseBasicParsing -TimeoutSec 2 -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "Backend is ready"
            $backendReady = $true
            break
        }
    } catch { }
}

if (-not $backendReady) {
    Write-Host "Warning: Backend did not start properly"
}

Write-Host "Starting frontend service..."
$FrontendDir = Join-Path $ProjectRoot "frontend"
if (-not (Test-Path $FrontendDir)) {
    Write-Host "Error: Frontend directory not found"
    exit 1
}

Push-Location $FrontendDir
if (-not (Test-Path "node_modules")) {
    Write-Host "Installing frontend dependencies..."
    npm install
}

Write-Host "Frontend will start in this window..."
Write-Host "========================================"
Write-Host "Backend: http://127.0.0.1:${BackendPort}"
Write-Host "Frontend: http://127.0.0.1:${FrontendPort}"
Write-Host "========================================"
Write-Host ""

npm run start