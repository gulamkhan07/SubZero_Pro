@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title SubZero - by Gulam Khan

:: Check if launched without arguments (interactive mode)
set "INTERACTIVE=0"
if "%~1"=="" set "INTERACTIVE=1"

:: Ensure bin directory exists
if not exist "bin" mkdir bin

:: ----------------------------------------------------------------
:: Step 1: Detect system uv
:: ----------------------------------------------------------------
where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    uv run --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python "%~dp0cli.py" %*
    goto finish
)

:: ----------------------------------------------------------------
:: Step 2: Detect portable uv in bin\uv.exe
:: ----------------------------------------------------------------
if exist "%~dp0bin\uv.exe" (
    "%~dp0bin\uv.exe" run --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python "%~dp0cli.py" %*
    goto finish
)

:: ----------------------------------------------------------------
:: Step 3: Detect local virtualenv (.venv)
:: ----------------------------------------------------------------
if exist "%~dp0.venv\Scripts\python.exe" (
    "%~dp0.venv\Scripts\python.exe" "%~dp0cli.py" %*
    goto finish
)

:: ----------------------------------------------------------------
:: Step 4: Detect Python Launcher (py)
:: ----------------------------------------------------------------
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if not exist "%~dp0.venv\Scripts\activate.bat" (
        echo [*] First-time setup on this PC: Creating isolated virtualenv...
        py -m venv "%~dp0.venv"
    )
    call "%~dp0.venv\Scripts\activate.bat"
    pip install -q -r "%~dp0requirements.txt"
    python "%~dp0cli.py" %*
    goto finish
)

:: ----------------------------------------------------------------
:: Step 5: Detect system Python (python.exe)
:: ----------------------------------------------------------------
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    if not exist "%~dp0.venv\Scripts\activate.bat" (
        echo [*] First-time setup on this PC: Creating isolated virtualenv...
        python -m venv "%~dp0.venv"
    )
    call "%~dp0.venv\Scripts\activate.bat"
    pip install -q -r "%~dp0requirements.txt"
    python "%~dp0cli.py" %*
    goto finish
)

:: ----------------------------------------------------------------
:: Step 6: Zero-Dependency Portable Auto-Bootstrap (PowerShell)
:: If running on a brand new PC with NO Python or tools installed!
:: ----------------------------------------------------------------
echo [*] No Python installation detected on this computer.
echo [*] Auto-downloading portable high-speed engine via PowerShell (10MB)...

powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip', 'bin\uv_temp.zip'); Expand-Archive -Path 'bin\uv_temp.zip' -DestinationPath 'bin' -Force; Remove-Item 'bin\uv_temp.zip' -Force"

if exist "%~dp0bin\uv.exe" (
    echo [+] Portable engine setup successfully!
    "%~dp0bin\uv.exe" run --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python "%~dp0cli.py" %*
    goto finish
)

echo.
echo [ERROR] Automatic setup could not connect to download runner.
echo Please ensure your computer is connected to the internet, or install Python from:
echo   https://www.python.org/downloads/
echo.
pause
exit /b 1

:finish
if "%INTERACTIVE%"=="1" (
    echo.
    echo Reconnaissance finished. Press any key to exit...
    pause >nul
)
