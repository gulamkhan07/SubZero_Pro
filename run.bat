@echo off
setlocal enabledelayedexpansion

:: ============================================================================
:: SubZero Web Platform - Windows Launcher
:: Enterprise OSINT Reconnaissance, DNS Integrity & Attack Surface Auditor
:: Developed by: Gulam Khan
:: Version: 2.2.0
:: ============================================================================

title SubZero - by Gulam Khan

echo ============================================================================
echo     SubZero v2.2 - OSINT ^& DNS Reconnaissance Platform
echo     Developed by: Gulam Khan
echo ============================================================================
echo.

:: ----------------------------------------------------------------------------
:: 1. ENVIRONMENT CONFIGURATION & PATHS
:: ----------------------------------------------------------------------------
set "ROOT_DIR=%~dp0"
set "BIN_DIR=%ROOT_DIR%bin"
set "WORDLISTS_DIR=%ROOT_DIR%wordlists"
set "VENV_DIR=%ROOT_DIR%.venv"
set "VENV_ACTIVATE=%VENV_DIR%\Scripts\activate.bat"
set "VENV_PYTHON=%VENV_DIR%\Scripts\python.exe"
set "APP_SCRIPT=%ROOT_DIR%app.py"
set "INSTALL_TOOLS_SCRIPT=%ROOT_DIR%install_tools.py"
set "REQ_FILE=%ROOT_DIR%requirements.txt"
set "UV_WEB_DEPS=--with "flask>=3.0,<4" --with "requests>=2.31,<3" --with "dnspython>=2.6,<3""

:: Ensure directories exist
cd /d "%ROOT_DIR%"
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
if not exist "%WORDLISTS_DIR%" mkdir "%WORDLISTS_DIR%"


:: ----------------------------------------------------------------------------
:: 2. RUNTIME RESOLUTION PIPELINE
:: ----------------------------------------------------------------------------

:: [Priority 1] System-installed 'uv'
where uv >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Detected uv runtime engine in PATH.
    call :RUN_UV "uv"
    goto :FINISH
)

:: [Priority 2] Portable 'uv' in bin\uv.exe
if exist "%BIN_DIR%\uv.exe" (
    echo [*] Detected portable uv engine in bin\uv.exe.
    call :RUN_UV "%BIN_DIR%\uv.exe"
    goto :FINISH
)

:: [Priority 3] Pre-configured local virtual environment (.venv)
if exist "%VENV_PYTHON%" (
    echo [*] Detected local isolated virtual environment (.venv).
    call :RUN_VENV
    goto :FINISH
)

:: [Priority 4] Python Launcher ('py')
where py >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Detected Python launcher (py).
    call :SETUP_AND_RUN_PYTHON "py"
    goto :FINISH
)

:: [Priority 5] Standard Python in system PATH ('python')
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo [*] Detected Python in system PATH.
    call :SETUP_AND_RUN_PYTHON "python"
    goto :FINISH
)

:: [Priority 6] Zero-Dependency Bootstrap
goto :BOOTSTRAP_PORTABLE_ENGINE


:: ============================================================================
:: 3. EXECUTION SUBROUTINES
:: ============================================================================

:: ----------------------------------------------------------------------------
:: Subroutine: Run via UV (Fast, zero-maintenance)
:: ----------------------------------------------------------------------------
:RUN_UV
set "UV_RUNNER=%~1"
echo [*] Verifying external discovery tools ^& dictionaries...
"%UV_RUNNER%" run python "%INSTALL_TOOLS_SCRIPT%"
echo [*] Launching SubZero UI on http://127.0.0.1:5000...
start "" http://127.0.0.1:5000
"%UV_RUNNER%" run %UV_WEB_DEPS% python "%APP_SCRIPT%"
exit /b %ERRORLEVEL%


:: ----------------------------------------------------------------------------
:: Subroutine: Run via existing Virtual Environment (.venv)
:: ----------------------------------------------------------------------------
:RUN_VENV
echo [*] Verifying external discovery tools ^& dictionaries...
"%VENV_PYTHON%" "%INSTALL_TOOLS_SCRIPT%"
echo [*] Launching SubZero UI on http://127.0.0.1:5000...
start "" http://127.0.0.1:5000
"%VENV_PYTHON%" "%APP_SCRIPT%"
exit /b %ERRORLEVEL%


:: ----------------------------------------------------------------------------
:: Subroutine: Setup Virtual Environment & Run via System Python / Py
:: ----------------------------------------------------------------------------
:SETUP_AND_RUN_PYTHON
set "PY_CMD=%~1"

if not exist "%VENV_ACTIVATE%" (
    echo [*] Creating local isolated virtual environment (.venv)...
    %PY_CMD% -m venv "%VENV_DIR%"
    if %ERRORLEVEL% neq 0 (
        echo [!] Virtual environment setup failed with %PY_CMD%.
        goto :ERROR_HANDLER
    )
)

call "%VENV_ACTIVATE%"
if exist "%REQ_FILE%" (
    echo [*] Installing runtime Python dependencies...
    pip install -q -r "%REQ_FILE%"
)
echo [*] Verifying external discovery tools ^& dictionaries...
python "%INSTALL_TOOLS_SCRIPT%"
echo [*] Launching SubZero UI on http://127.0.0.1:5000...
start "" http://127.0.0.1:5000
python "%APP_SCRIPT%"
exit /b %ERRORLEVEL%


:: ----------------------------------------------------------------------------
:: Subroutine: Zero-Dependency Portable Engine Bootstrap via PowerShell
:: ----------------------------------------------------------------------------
:BOOTSTRAP_PORTABLE_ENGINE
echo [!] Neither Python nor uv was found on this system.
echo [*] Initiating automatic portable Python bootstrap via PowerShell...
echo [*] Downloading portable high-speed runner (10MB)...
echo.

set "UV_ZIP_URL=https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-pc-windows-msvc.zip"
set "UV_TEMP_ZIP=%BIN_DIR%\uv_temp.zip"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " ^
    "(New-Object Net.WebClient).DownloadFile('%UV_ZIP_URL%', '%UV_TEMP_ZIP%'); " ^
    "Expand-Archive -Path '%UV_TEMP_ZIP%' -DestinationPath '%BIN_DIR%' -Force; " ^
    "Remove-Item '%UV_TEMP_ZIP%' -Force"

if exist "%BIN_DIR%\uv.exe" (
    echo [+] Portable engine bootstrapped successfully into bin\uv.exe!
    call :RUN_UV "%BIN_DIR%\uv.exe"
    goto :FINISH
)

goto :ERROR_HANDLER


:: ----------------------------------------------------------------------------
:: Subroutine: Error Diagnostics
:: ----------------------------------------------------------------------------
:ERROR_HANDLER
echo.
echo [ERROR] Could not automatically configure Python environment.
echo Please ensure your computer is connected to the internet, or install Python 3.10+ from:
echo   https://www.python.org/downloads/
echo.
pause
exit /b 1


:: ----------------------------------------------------------------------------
:: Subroutine: Exit
:: ----------------------------------------------------------------------------
:FINISH
pause
exit /b %ERRORLEVEL%

