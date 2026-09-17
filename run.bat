@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title SubZero - by Gulam Khan

echo ========================================================
echo     SubZero v2.2 - OSINT & DNS Reconnaissance Platform
echo     Developed by: Gulam Khan
echo ========================================================
echo.

:: Ensure bin directory exists
if not exist "bin" mkdir bin

:: ----------------------------------------------------------------
:: Step 1: Check for uv (Fastest, zero-setup Python engine)
:: ----------------------------------------------------------------
where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Detected uv runtime engine.
    echo [*] Checking and downloading missing tools / wordlists...
    uv run python install_tools.py
    echo [*] Starting SubZero on http://127.0.0.1:5000...
    start "" http://127.0.0.1:5000
    uv run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
    goto end
)

:: Check if portable uv was previously auto-downloaded to bin\uv.exe
if exist "bin\uv.exe" (
    echo [*] Detected portable uv engine in bin\.
    echo [*] Checking and downloading missing tools / wordlists...
    bin\uv.exe run python install_tools.py
    echo [*] Starting SubZero on http://127.0.0.1:5000...
    start "" http://127.0.0.1:5000
    bin\uv.exe run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
    goto end
)

:: ----------------------------------------------------------------
:: Step 2: Check for Python Launcher (py)
:: ----------------------------------------------------------------
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Detected Python launcher (py).
    if not exist ".venv\Scripts\activate.bat" (
        echo [*] Creating local isolated virtual environment (.venv)...
        py -m venv .venv
    )
    call .venv\Scripts\activate.bat
    echo [*] Verifying Python dependencies...
    pip install -q -r requirements.txt
    echo [*] Checking and downloading missing tools / wordlists...
    python install_tools.py
    echo [*] Starting SubZero on http://127.0.0.1:5000...
    start "" http://127.0.0.1:5000
    python app.py
    goto end
)

:: ----------------------------------------------------------------
:: Step 3: Check for standard Python (python.exe)
:: ----------------------------------------------------------------
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Detected Python in system PATH.
    if not exist ".venv\Scripts\activate.bat" (
        echo [*] Creating local isolated virtual environment (.venv)...
        python -m venv .venv
    )
    call .venv\Scripts\activate.bat
    echo [*] Verifying Python dependencies...
    pip install -q -r requirements.txt
    echo [*] Checking and downloading missing tools / wordlists...
    python install_tools.py
    echo [*] Starting SubZero on http://127.0.0.1:5000...
    start "" http://127.0.0.1:5000
    python app.py
    goto end
)

:: ----------------------------------------------------------------
:: Step 4: ZERO-DEPENDENCY AUTO-DOWNLOAD (PowerShell)
:: If user has NO Python installed on their machine!
:: ----------------------------------------------------------------
echo [!] Neither Python nor uv was found on this system.
echo [*] Initiating automatic portable Python bootstrap via PowerShell...
echo [*] Downloading portable high-speed runner (10MB)...

powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip', 'bin\uv_temp.zip'); Expand-Archive -Path 'bin\uv_temp.zip' -DestinationPath 'bin' -Force; Remove-Item 'bin\uv_temp.zip' -Force"

if exist "bin\uv.exe" (
    echo [+] Portable engine setup successfully!
    echo [*] Installing discovery tools & wordlists...
    bin\uv.exe run python install_tools.py
    echo [*] Starting SubZero on http://127.0.0.1:5000...
    start "" http://127.0.0.1:5000
    bin\uv.exe run --with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python app.py
    goto end
)

echo.
echo [ERROR] Automatic setup could not connect to download runner.
echo Please ensure your computer is connected to the internet, or install Python 3.10+ from:
echo   https://www.python.org/downloads/
echo.
pause
exit /b 1

:end
pause
