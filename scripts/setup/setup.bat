@echo off
setlocal
pushd "%~dp0..\.."
set "ROOT_DIR=%CD%"
popd

echo =======================================================
echo   SECURITY GUARD - Setting Up Development Environment
echo   Project Root: "%ROOT_DIR%"
echo =======================================================

:: Check Node.js
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not in PATH!
    exit /b 1
)

:: Check npm
where npm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] npm is not installed or not in PATH!
    exit /b 1
)

:: Check Python
where python >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python is not installed or not in PATH!
    exit /b 1
)

echo [1/3] Installing Web Application dependencies...
cd /d "%ROOT_DIR%\web-app"
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install Web App dependencies.
    exit /b %ERRORLEVEL%
)

echo [2/3] Setting up Detection Engine Python virtualenv...
cd /d "%ROOT_DIR%\detection-engine"
if not exist "venv\Scripts\python.exe" (
    python -m venv venv
)
call venv\Scripts\activate.bat
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [WARNING] Some Python packages could not be installed immediately. You can retry later.
)
call deactivate

echo [3/3] Installing Dashboard dependencies...
cd /d "%ROOT_DIR%\dashboard"
call npm install
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install Dashboard dependencies.
    exit /b %ERRORLEVEL%
)

echo.
echo =======================================================
echo   Setup completed successfully!
echo =======================================================
