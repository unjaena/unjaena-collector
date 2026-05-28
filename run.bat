@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion

echo ============================================
echo   Digital Forensics Collector - Windows
echo ============================================
echo.

:: Check Python 3.10+
set "PYTHON_CMD="
where python >nul 2>&1
if %errorlevel% equ 0 (
    for /f "tokens=*" %%i in ('python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PY_VER=%%i"
    for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
        if %%a geq 3 if %%b geq 10 set "PYTHON_CMD=python"
    )
)

if not defined PYTHON_CMD (
    where python3 >nul 2>&1
    if %errorlevel% equ 0 (
        for /f "tokens=*" %%i in ('python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2^>nul') do set "PY_VER=%%i"
        for /f "tokens=1,2 delims=." %%a in ("!PY_VER!") do (
            if %%a geq 3 if %%b geq 10 set "PYTHON_CMD=python3"
        )
    )
)

if not defined PYTHON_CMD (
    echo [ERROR] Python 3.10+ is required but not found.
    echo         Download from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Found Python !PY_VER! (!PYTHON_CMD!)

:: Navigate to collector directory
cd /d "%~dp0"

:: Create venv if not exists
if not exist ".venv\Scripts\activate.bat" (
    echo.
    echo [INFO] Creating virtual environment...
    !PYTHON_CMD! -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
)

:: Activate venv
call .venv\Scripts\activate.bat

:: Install dependencies
echo.
echo [INFO] Installing dependencies...
pip install -r requirements\windows.txt --quiet
if %errorlevel% neq 0 (
    echo [WARN] Some packages failed to install. Trying base packages only...
    pip install -r requirements\base.txt --quiet
)
echo [OK] Dependencies installed.

:: Launch application
echo.
echo [INFO] Starting collector...
echo.
python src\main.py
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Application exited with error code %errorlevel%.
    pause
)

endlocal
