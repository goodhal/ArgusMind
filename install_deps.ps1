<#
.SYNOPSIS
ArgusMind 外部依赖安装脚本

.DESCRIPTION
此脚本用于安装 ArgusMind 项目所需的所有外部工具：
1. PostgreSQL 数据库
2. Neo4j 图数据库
3. Node.js（前端依赖）
4. Python 虚拟环境及依赖

.NOTES
- 运行此脚本需要管理员权限
- 建议在 PowerShell 7+ 环境下运行
- 安装过程可能需要较长时间，请耐心等待
#>

$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "     ArgusMind 外部依赖安装脚本" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 检查管理员权限
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "错误: 此脚本需要管理员权限运行" -ForegroundColor Red
    Write-Host "请右键点击 PowerShell 并选择 '以管理员身份运行'" -ForegroundColor Yellow
    exit 1
}

# ========================================
# 1. 安装 PostgreSQL
# ========================================
Write-Host "[1/4] 检查 PostgreSQL..." -ForegroundColor Cyan

try {
    $pgVersion = & "psql" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "PostgreSQL 已安装: $pgVersion" -ForegroundColor Green
    } else {
        Write-Host "PostgreSQL 未安装，开始安装..." -ForegroundColor Yellow
        
        # 使用 Chocolatey 安装 PostgreSQL
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "安装 Chocolatey..." -ForegroundColor Gray
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        Write-Host "安装 PostgreSQL 16..." -ForegroundColor Gray
        choco install postgresql16 -y --params "/Password:YourPgPassword123!"
        
        # 添加 PostgreSQL 到 PATH
        $pgPath = "C:\Program Files\PostgreSQL\16\bin"
        if (-not ($env:PATH -like "*$pgPath*")) {
            [Environment]::SetEnvironmentVariable("PATH", "$($env:PATH);$pgPath", [EnvironmentVariableTarget]::Machine)
            $env:PATH += ";$pgPath"
        }
        
        Write-Host "PostgreSQL 安装完成" -ForegroundColor Green
    }
} catch {
    Write-Host "PostgreSQL 安装检查失败: $_" -ForegroundColor Red
}

# ========================================
# 2. 安装 Neo4j
# ========================================
Write-Host "`n[2/4] 检查 Neo4j..." -ForegroundColor Cyan

try {
    $neo4jVersion = & "neo4j" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Neo4j 已安装: $neo4jVersion" -ForegroundColor Green
    } else {
        Write-Host "Neo4j 未安装，开始安装..." -ForegroundColor Yellow
        
        # 检查 Java 是否安装
        try {
            $javaVersion = & "java" -version 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "安装 Java 21..." -ForegroundColor Gray
                choco install temurin21 -y
            }
        } catch {
            Write-Host "安装 Java 21..." -ForegroundColor Gray
            choco install temurin21 -y
        }
        
        Write-Host "下载并安装 Neo4j 5.22..." -ForegroundColor Gray
        
        # 创建 Neo4j 目录
        $neo4jDir = "C:\neo4j"
        if (-not (Test-Path $neo4jDir)) {
            New-Item -ItemType Directory -Path $neo4jDir | Out-Null
        }
        
        # 下载 Neo4j 社区版
        $zipPath = "$neo4jDir\neo4j.zip"
        Invoke-WebRequest -Uri "https://neo4j.com/artifact.php?name=neo4j-community-5.22.0-windows-x64.zip" -OutFile $zipPath
        
        # 解压
        Expand-Archive -Path $zipPath -DestinationPath $neo4jDir -Force
        
        # 添加到 PATH
        $neo4jBin = "$neo4jDir\neo4j-community-5.22.0\bin"
        if (-not ($env:PATH -like "*$neo4jBin*")) {
            [Environment]::SetEnvironmentVariable("PATH", "$($env:PATH);$neo4jBin", [EnvironmentVariableTarget]::Machine)
            $env:PATH += ";$neo4jBin"
        }
        
        Write-Host "Neo4j 安装完成" -ForegroundColor Green
    }
} catch {
    Write-Host "Neo4j 安装检查失败: $_" -ForegroundColor Red
}

# ========================================
# 3. 安装 Node.js
# ========================================
Write-Host "`n[3/4] 检查 Node.js..." -ForegroundColor Cyan

try {
    $nodeVersion = & "node" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Node.js 已安装: $nodeVersion" -ForegroundColor Green
        
        # 检查版本是否 >= 20
        $versionNumber = $nodeVersion -replace "v", ""
        if ([version]$versionNumber -lt [version]"20.0.0") {
            Write-Host "Node.js 版本过低，需要 >= 20.0.0" -ForegroundColor Yellow
            choco install nodejs-lts -y
        }
    } else {
        Write-Host "Node.js 未安装，开始安装..." -ForegroundColor Yellow
        choco install nodejs-lts -y
        $env:PATH += ";C:\Program Files\nodejs"
        Write-Host "Node.js 安装完成" -ForegroundColor Green
    }
    
    # 安装 pnpm（可选，提高安装速度）
    if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) {
        Write-Host "安装 pnpm..." -ForegroundColor Gray
        npm install -g pnpm
    }
} catch {
    Write-Host "Node.js 安装检查失败: $_" -ForegroundColor Red
}

# ========================================
# 4. 配置数据库
# ========================================
Write-Host "`n[4/4] 配置数据库..." -ForegroundColor Cyan

# 创建 PostgreSQL 数据库和用户
try {
    Write-Host "创建 PostgreSQL 用户和数据库..." -ForegroundColor Gray
    
    $pgPassword = "YourPgPassword123!"
    $pgUser = "argusmind"
    $pgDb = "argusmind"
    
    # 创建用户
    & psql -U postgres -c "CREATE USER $pgUser WITH PASSWORD '$pgPassword';" 2>&1 | Out-Null
    
    # 创建数据库
    & psql -U postgres -c "CREATE DATABASE $pgDb OWNER $pgUser;" 2>&1 | Out-Null
    
    Write-Host "PostgreSQL 配置完成" -ForegroundColor Green
} catch {
    Write-Host "PostgreSQL 配置失败（可能已存在）: $_" -ForegroundColor Yellow
}

# 配置 Neo4j
try {
    Write-Host "配置 Neo4j 密码..." -ForegroundColor Gray
    
    # 设置初始密码
    neo4j-admin dbms set-initial-password YourNeo4jPassword123! 2>&1 | Out-Null
    
    Write-Host "Neo4j 配置完成" -ForegroundColor Green
} catch {
    Write-Host "Neo4j 配置失败: $_" -ForegroundColor Yellow
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "     外部依赖安装完成！" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "下一步操作：" -ForegroundColor White
Write-Host "1. 启动 PostgreSQL 服务: net start postgresql-x64-16" -ForegroundColor Gray
Write-Host "2. 启动 Neo4j 服务: neo4j start" -ForegroundColor Gray
Write-Host "3. 创建 .env 文件并配置数据库连接" -ForegroundColor Gray
Write-Host "4. 安装 Python 依赖: pip install -r requirements.txt" -ForegroundColor Gray
Write-Host "5. 启动应用: .\start.ps1" -ForegroundColor Gray
Write-Host ""