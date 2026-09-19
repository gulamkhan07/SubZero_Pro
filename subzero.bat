@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: SubZero CLI - Windows Portable Launcher
:: High-Speed OSINT & DNS Reconnaissance Engine
:: Developed by: Gulam Khan
:: Version: 2.2.0
:: ============================================================================

title SubZero - by Gulam Khan

:: ----------------------------------------------------------------------------
:: 1. ENVIRONMENT CONFIGURATION & PATHS
:: ----------------------------------------------------------------------------
set "ROOT_DIR=%~dp0"
set "BIN_DIR=%ROOT_DIR%bin"
set "VENV_DIR=%ROOT_DIR%.venv"
set "VENV_ACTIVATE=%VENV_DIR%\Scripts\activate.bat"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "CLI_SCRIPT=%ROOT_DIR%cli.py"
set "REQ_FILE=%ROOT_DIR%requirements.txt"
set "APP_ARGS=%*"

:: Ensure working directory is project root
cd /d "%ROOT_DIR%"

:: Create bin directory if absent
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"

:: Check execution mode (Interactive UI if no args, Direct CLI if args passed)
set "IS_INTERACTIVE=0"
if "%~1"=="" set "IS_INTERACTIVE=1"


:: ----------------------------------------------------------------------------
:: 2. RUNTIME RESOLUTION PIPELINE (FASTEST TO PORTABLE FALLBACK)
:: ----------------------------------------------------------------------------

:: [Priority 1] System-installed 'uv' (Instant startup)
where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    call :RUN_UV "uv"
    goto :FINISH
)

:: [Priority 2] Portable 'uv' in bin\uv.exe
if exist "%BIN_DIR%\uv.exe" (
    call :RUN_UV "%BIN_DIR%\uv.exe"
    goto :FINISH
)

:: [Priority 3] Pre-configured local virtual environment (.venv)
if exist "%VENV_PYTHON%" (
    call :RUN_VENV
    goto :FINISH
)

:: [Priority 4] Python Launcher ('py')
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    call :SETUP_AND_RUN_PYTHON "py"
    goto :FINISH
)

:: [Priority 5] Standard Python in system PATH ('python')
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    call :SETUP_AND_RUN_PYTHON "python"
    goto :FINISH
)

:: [Priority 6] Zero-Dependency Bootstrap (Fresh PC with NO Python)
goto :BOOTSTRAP_PORTABLE_ENGINE


:: ============================================================================
:: 3. EXECUTION SUBROUTINES (MODULAR & REUSABLE)
:: ============================================================================

:: ----------------------------------------------------------------------------
:: Subroutine: Run via UV (Zero-setup ephemeral environment)
:: ----------------------------------------------------------------------------
:RUN_UV
set "UV_RUNNER=%~1"
"%UV_RUNNER%" run --with "requests>=2.31,<3" --with "dnspython>=2.6,<3" python "%CLI_SCRIPT%" %APP_ARGS%
exit /b %ERRORLEVEL%


:: ----------------------------------------------------------------------------
:: Subroutine: Run via existing Virtual Environment (.venv)
:: ----------------------------------------------------------------------------
:RUN_VENV
"%VENV_PYTHON%" "%CLI_SCRIPT%" %APP_ARGS%
exit /b %ERRORLEVEL%


:: ----------------------------------------------------------------------------
:: Subroutine: Setup Virtual Environment & Run via System Python / Py
:: ----------------------------------------------------------------------------
:SETUP_AND_RUN_PYTHON
set "PY_CMD=%~1"

if not exist "%VENV_ACTIVATE%" (
    echo [*] First-time setup detected on this computer.
    echo [*] Creating isolated virtual environment (.venv)...
    %PY_CMD% -m venv "%VENV_DIR%"
    if %ERRORLEVEL% neq 0 (
        echo [!] Failed to create virtual environment with %PY_CMD%.
        goto :ERROR_HANDLER
    )
)

call "%VENV_ACTIVATE%"
if exist "%REQ_FILE%" (
    pip install -q -r "%REQ_FILE%"
)
python "%CLI_SCRIPT%" %APP_ARGS%
exit /b %ERRORLEVEL%


:: ----------------------------------------------------------------------------
:: Subroutine: Zero-Dependency Portable Engine Bootstrap via PowerShell
:: ----------------------------------------------------------------------------
:BOOTSTRAP_PORTABLE_ENGINE
echo ============================================================================
echo   SubZero Portable Engine Auto-Bootstrap
echo ============================================================================
echo [*] No Python or UV installation detected on this computer.
echo [*] Downloading ultra-fast portable runner (10MB) via PowerShell...
echo.

set "UV_ZIP_URL=https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip"
set "UV_TEMP_ZIP=%BIN_DIR%\uv_temp.zip"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " ^
    "(New-Object Net.WebClient).DownloadFile('%UV_ZIP_URL%', '%UV_TEMP_ZIP%'); " ^
    "Expand-Archive -Path '%UV_TEMP_ZIP%' -DestinationPath '%BIN_DIR%' -Force; " ^
    "Remove-Item '%UV_TEMP_ZIP%' -Force"

if exist "%BIN_DIR%\uv.exe" (
    echo.
    echo [+] Portable engine bootstrapped successfully into bin\uv.exe!
    echo [*] Launching SubZero CLI...
    echo.
    call :RUN_UV "%BIN_DIR%\uv.exe"
    goto :FINISH
)

goto :ERROR_HANDLER


:: ----------------------------------------------------------------------------
:: Subroutine: Error Diagnostics
:: ----------------------------------------------------------------------------
:ERROR_HANDLER
echo.
echo [!] ERROR: Could not launch SubZero reconnaissance engine.
echo [!] Please ensure you have internet access or install Python from:
echo       https://www.python.org/downloads/
echo.
if "%IS_INTERACTIVE%"=="1" pause
exit /b 1


:: ----------------------------------------------------------------------------
:: Subroutine: Exit & Cleanup
:: ----------------------------------------------------------------------------
:FINISH
set "EXIT_CODE=%ERRORLEVEL%"
if "%IS_INTERACTIVE%"=="1" (
    echo.
    echo Reconnaissance finished. Press any key to exit...
    pause >nul
)
exit /b %EXIT_CODE%
