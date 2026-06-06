<#
.SYNOPSIS
ArgusMind Code Audit Tools Installation Script

.DESCRIPTION
This script installs all external tools required by ArgusMind code audit:

[Information Collection Phase Tools]
1. Tokei - Code language statistics (file count, line count)
2. Ripgrep (rg) - Fast code search tool (auto-downloads if not present)
3. GitNexus - Code knowledge graph (analyzes code structure and call relationships)
4. OpenCode - AI code analysis tool

[Security Scan Phase Tools]
5. Gitleaks - Secret and sensitive information detection
6. Bandit - Python code security analysis
7. Semgrep - Multi-language static analysis

[Dependencies]
- Node.js >= 20.0.0 (for OpenCode, GitNexus)
- Python >= 3.10 (for Bandit, Semgrep)

.NOTES
- Run this script with administrator privileges
- PowerShell 7+ recommended
- Ripgrep auto-downloads on first run, but manual installation speeds it up
#>

$ErrorActionPreference = "Continue"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "    ArgusMind Tools Installation Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Note: Chocolatey installation requires administrator privileges
# If you encounter permission errors, run PowerShell as Administrator
Write-Host "Note: Some tools may require admin rights to install" -ForegroundColor Yellow

# ========================================
# 1. Install Tokei
# ========================================
Write-Host "[1/7] Installing Tokei..." -ForegroundColor Cyan

try {
    $tokeiVersion = & "tokei" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Tokei is already installed: $tokeiVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing Tokei..." -ForegroundColor Yellow
        
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "Installing Chocolatey..." -ForegroundColor Gray
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        choco install tokei -y
        Write-Host "Tokei installed successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to install Tokei: $_" -ForegroundColor Red
}

# ========================================
# 2. Install Ripgrep
# ========================================
Write-Host "`n[2/7] Installing Ripgrep..." -ForegroundColor Cyan

try {
    $ripgrepVersion = & "rg" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Ripgrep is already installed: $ripgrepVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing Ripgrep..." -ForegroundColor Yellow
        
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "Installing Chocolatey..." -ForegroundColor Gray
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        choco install ripgrep -y
        Write-Host "Ripgrep installed successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to install Ripgrep: $_" -ForegroundColor Red
}

# ========================================
# 3. Install GitNexus
# ========================================
Write-Host "`n[3/7] Installing GitNexus..." -ForegroundColor Cyan

try {
    $gitnexusVersion = & "gitnexus" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "GitNexus is already installed: $gitnexusVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing GitNexus..." -ForegroundColor Yellow
        
        try {
            $nodeVersion = & "node" --version 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Node.js not found, installing..." -ForegroundColor Gray
                choco install nodejs-lts -y
                $env:PATH += ";C:\Program Files\nodejs"
            }
        } catch {
            Write-Host "Installing Node.js..." -ForegroundColor Gray
            choco install nodejs-lts -y
            $env:PATH += ";C:\Program Files\nodejs"
        }
        
        Write-Host "Installing gitnexus via npm..." -ForegroundColor Gray
        $result = npm install -g gitnexus@latest --registry https://registry.npmmirror.com 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed with CN registry, trying default..." -ForegroundColor Yellow
            $result = npm install -g gitnexus@latest 2>&1
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "GitNexus installed successfully" -ForegroundColor Green
        } else {
            Write-Host "Failed to install GitNexus: $result" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Failed to install GitNexus: $_" -ForegroundColor Red
}

# ========================================
# 4. Install Gitleaks
# ========================================
Write-Host "`n[4/7] Installing Gitleaks..." -ForegroundColor Cyan

try {
    $gitleaksVersion = & "gitleaks" version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Gitleaks is already installed: $gitleaksVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing Gitleaks..." -ForegroundColor Yellow
        
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "Installing Chocolatey..." -ForegroundColor Gray
            Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
        }
        
        choco install gitleaks -y
        Write-Host "Gitleaks installed successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to install Gitleaks: $_" -ForegroundColor Red
}

# ========================================
# 5. Install Bandit
# ========================================
Write-Host "`n[5/7] Installing Bandit..." -ForegroundColor Cyan

try {
    $banditVersion = & "bandit" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Bandit is already installed: $banditVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing Bandit..." -ForegroundColor Yellow
        pip install bandit
        Write-Host "Bandit installed successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to install Bandit: $_" -ForegroundColor Red
}

# ========================================
# 6. Install Semgrep
# ========================================
Write-Host "`n[6/7] Installing Semgrep..." -ForegroundColor Cyan

try {
    $semgrepVersion = & "semgrep" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Semgrep is already installed: $semgrepVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing Semgrep..." -ForegroundColor Yellow
        pip install semgrep
        Write-Host "Semgrep installed successfully" -ForegroundColor Green
    }
} catch {
    Write-Host "Failed to install Semgrep: $_" -ForegroundColor Red
}

# ========================================
# 7. Install OpenCode
# ========================================
Write-Host "`n[7/7] Installing OpenCode..." -ForegroundColor Cyan

try {
    $opencodeVersion = & "opencode" --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "OpenCode is already installed: $opencodeVersion" -ForegroundColor Green
    } else {
        Write-Host "Installing OpenCode..." -ForegroundColor Yellow
        
        try {
            $nodeVersion = & "node" --version 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-Host "Node.js not found, installing..." -ForegroundColor Gray
                choco install nodejs-lts -y
                $env:PATH += ";C:\Program Files\nodejs"
            }
        } catch {
            Write-Host "Installing Node.js..." -ForegroundColor Gray
            choco install nodejs-lts -y
            $env:PATH += ";C:\Program Files\nodejs"
        }
        
        Write-Host "Installing opencode-ai via npm..." -ForegroundColor Gray
        $result = npm install -g opencode-ai --registry https://registry.npmmirror.com 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Host "Failed with CN registry, trying default..." -ForegroundColor Yellow
            $result = npm install -g opencode-ai 2>&1
        }
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "OpenCode installed successfully" -ForegroundColor Green
        } else {
            Write-Host "Failed to install OpenCode: $result" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Failed to install OpenCode: $_" -ForegroundColor Red
}

# ========================================
# Verify Installation
# ========================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "          Installation Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "`n[Information Collection Tools]" -ForegroundColor Yellow
Write-Host "Checking Tokei:" -ForegroundColor White
& tokei --version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "Checking Ripgrep:" -ForegroundColor White
& rg --version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "Checking GitNexus:" -ForegroundColor White
& gitnexus --version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "Checking OpenCode:" -ForegroundColor White
& opencode --version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "`n[Security Scan Tools]" -ForegroundColor Yellow
Write-Host "Checking Gitleaks:" -ForegroundColor White
& gitleaks version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "Checking Bandit:" -ForegroundColor White
& bandit --version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "Checking Semgrep:" -ForegroundColor White
& semgrep --version 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Host "OK" -ForegroundColor Green } else { Write-Host "FAILED" -ForegroundColor Red }

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "          Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Installed tools:" -ForegroundColor White
Write-Host ""
Write-Host "[Information Collection Tools]" -ForegroundColor Yellow
Write-Host "- Tokei: Code language statistics" -ForegroundColor Gray
Write-Host "- Ripgrep (rg): Fast code search" -ForegroundColor Gray
Write-Host "- GitNexus: Code knowledge graph" -ForegroundColor Gray
Write-Host "- OpenCode: AI code analysis" -ForegroundColor Gray
Write-Host ""
Write-Host "[Security Scan Tools]" -ForegroundColor Yellow
Write-Host "- Gitleaks: Secret detection" -ForegroundColor Gray
Write-Host "- Bandit: Python security analysis" -ForegroundColor Gray
Write-Host "- Semgrep: Multi-language static analysis" -ForegroundColor Gray
Write-Host ""
Write-Host "These tools will be automatically used during code audit" -ForegroundColor White