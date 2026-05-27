# ArgusMind 一键安装（Windows PowerShell）
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Write-Info([string]$Message) {
    Write-Host "[ArgusMind] $Message"
}

function Write-Err([string]$Message) {
    Write-Host "[ArgusMind] 错误: $Message" -ForegroundColor Red
    exit 1
}

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Err "未找到 docker，请先安装 Docker Desktop: https://docs.docker.com/desktop/install/windows-install/"
}

$composeArgs = @("compose")
$null = & docker compose version 2>$null
if ($LASTEXITCODE -ne 0) {
    if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
        $composeArgs = @()
        $ComposeCmd = { param($Args) & docker-compose @Args }
    } else {
        Write-Err "未找到 docker compose，请安装 Docker Compose V2"
    }
} else {
    $ComposeCmd = { param($Args) & docker @composeArgs @Args }
}

$EnvFile = Join-Path $Root ".env"
$EnvExample = Join-Path $Root ".env.docker.example"
$CreatedEnv = $false
$NewPgPassword = $null
$NewNeo4jPassword = $null

function New-RandomDbPassword {
    param([int]$Length = 24)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    -join (1..$Length | ForEach-Object { $chars[(Get-Random -Maximum $chars.Length)] })
}

function Write-EnvWithRandomPasswords {
    param([string]$ExamplePath, [string]$OutPath)
    $script:NewPgPassword = New-RandomDbPassword
    $script:NewNeo4jPassword = New-RandomDbPassword
    $lines = Get-Content $ExamplePath | ForEach-Object {
        if ($_ -match '^POSTGRES_PASSWORD=') { "POSTGRES_PASSWORD=$($script:NewPgPassword)" }
        elseif ($_ -match '^NEO4J_PASSWORD=') { "NEO4J_PASSWORD=$($script:NewNeo4jPassword)" }
        else { $_ }
    }
    [System.IO.File]::WriteAllLines($OutPath, $lines)
    $script:CreatedEnv = $true
    Write-Info "已生成 .env，PostgreSQL / Neo4j 密码为随机值（见安装完成提示或 .env 文件）"
}

if (-not (Test-Path $EnvFile)) {
    if (Test-Path $EnvExample) {
        Write-EnvWithRandomPasswords -ExamplePath $EnvExample -OutPath $EnvFile
    } else {
        Write-Err "缺少 .env.docker.example"
    }
}

$DataDir = "data"
Get-Content $EnvFile -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_ -match '^\s*DATA_DIR\s*=\s*(.+)\s*$') {
        $DataDir = $Matches[1].Trim().Trim('"').Trim("'") -replace '^\./', ''
    }
}
$DataRoot = Join-Path $Root $DataDir
@("postgres", "neo4j", "work", "repos") | ForEach-Object {
    New-Item -ItemType Directory -Force -Path (Join-Path $DataRoot $_) | Out-Null
}

Write-Info "构建并启动服务（PostgreSQL + Neo4j + API）..."
& docker @composeArgs -f docker-compose.yml up -d --build
if ($LASTEXITCODE -ne 0) { Write-Err "docker compose up 失败" }

# 读取端口
$Port = 6066
Get-Content $EnvFile | ForEach-Object {
    if ($_ -match '^\s*ARGUSMIND_PORT\s*=\s*(\d+)\s*$') {
        $Port = [int]$Matches[1]
    }
}

Write-Info "等待 API 就绪..."
$ready = $false
for ($i = 1; $i -le 90; $i++) {
    try {
        $resp = Invoke-WebRequest -Uri "http://localhost:$Port/api/health" -UseBasicParsing -TimeoutSec 3
        if ($resp.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        # 继续等待
    }
    Start-Sleep -Seconds 2
}
if (-not $ready) {
    Write-Err "API 启动超时，请执行: docker compose -f docker-compose.yml logs argusmind"
}

Write-Host @"

========================================
 ArgusMind 安装完成
========================================
 API 地址:     http://localhost:$Port
 API 文档:     http://localhost:$Port/docs
 健康检查:     http://localhost:$Port/api/ready

 默认登录:     用户名 ArgusMind  密码 ArgusMind
 （生产环境请尽快修改密码）
"@

if ($CreatedEnv) {
    $pgUser = "argusmind"
    $neoUser = "neo4j"
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*POSTGRES_USER\s*=\s*(.+)\s*$') { $pgUser = $Matches[1].Trim() }
        if ($_ -match '^\s*NEO4J_USER\s*=\s*(.+)\s*$') { $neoUser = $Matches[1].Trim() }
    }
    Write-Host @"

 数据库凭据（已写入 .env，请妥善保管）:
   PostgreSQL  用户 $pgUser  密码 $NewPgPassword
   Neo4j       用户 $neoUser  密码 $NewNeo4jPassword
"@
}

Write-Host @"

 数据目录:     .\$DataDir\postgres  PostgreSQL
               .\$DataDir\neo4j     Neo4j
               .\$DataDir\work      应用工作区
               .\$DataDir\repos     被测代码（容器路径 /data/repos/...）

 常用命令:
   查看日志:   docker compose -f docker-compose.yml logs -f argusmind
   停止服务:   docker compose -f docker-compose.yml down
   清空数据库: 先 down，再手动删除 .\$DataDir\postgres 与 .\$DataDir\neo4j

 启动后请在「配置管理」中填写 LLM 与 Code Agent 密钥。
========================================
"@
