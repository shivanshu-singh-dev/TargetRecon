# PowerShell launcher for Algorithm-Optimized Reconnaissance Framework Dashboard
param(
    [switch]$Dev = $false,
    [switch]$OpenBrowser = $true
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Set-Location $ScriptDir

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Algorithm-Optimized Reconnaissance Framework - Dashboard Launcher" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"

if (-not (Test-Path $VenvPython)) {
    Write-Host "[-] Virtual environment not detected at .venv" -ForegroundColor Yellow
    Write-Host "[*] Creating .venv and installing requirements..." -ForegroundColor Yellow
    python -m venv .venv
    & "$ScriptDir\.venv\Scripts\pip.exe" install -r "$ScriptDir\requirements.txt"
}

if ($Dev) {
    Write-Host "[*] Starting in Frontend Dev Mode (Vite + FastAPI backend)..." -ForegroundColor Green
    Write-Host "[*] Starting FastAPI Backend on port 8000..." -ForegroundColor Gray
    Start-Process -FilePath $VenvPython -ArgumentList "api_server.py" -WorkingDirectory $ScriptDir

    Write-Host "[*] Starting Vite Dev Server on port 5173..." -ForegroundColor Gray
    Set-Location (Join-Path $ScriptDir "frontend")
    npm.cmd run dev
} else {
    Write-Host "[*] Starting Unified FastAPI Server hosting React Dashboard on http://127.0.0.1:8000" -ForegroundColor Green
    if ($OpenBrowser) {
        Start-Process "http://127.0.0.1:8000"
    }
    & $VenvPython "api_server.py"
}
