@echo off
setlocal
cd /d "%~dp0"

echo =====================================================================
echo  Algorithm-Optimized Reconnaissance Framework - Dashboard Launcher
echo =====================================================================

if not exist ".venv\Scripts\python.exe" (
    echo [-] Virtual environment not found in .venv\
    echo [*] Creating virtual environment and installing dependencies...
    python -m venv .venv
    call .venv\Scripts\activate.bat
    pip install -r requirements.txt
) else (
    call .venv\Scripts\activate.bat
)

echo [*] Starting FastAPI Recon Dashboard Server on http://127.0.0.1:8000
echo [*] Press Ctrl+C to stop the server.
echo.

python api_server.py

pause
