@echo off
setlocal
pushd "%~dp0..\.."
set "ROOT_DIR=%CD%"
popd

echo =======================================================
echo   Running SECURITY GUARD Automated Tests (Phase 1-8)
echo   Rule-Based ^& Machine Learning Anomaly Detection
echo   Project Root: "%ROOT_DIR%"
echo =======================================================

:: Prerequisite Environment Checks
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not in PATH!
    exit /b 1
)

where npm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] npm is not installed or not in PATH!
    exit /b 1
)

:: Database Availability Check
netstat -aon 2>nul | findstr ":5432 " | findstr "LISTENING" >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [OK] PostgreSQL is ONLINE on port 5432
) else (
    echo [WARN] PostgreSQL unavailable on port 5432
    echo        Web App will run in resilient file-only degradation mode.
)

echo.
echo [1/2] Testing Web Application, Logging, and Database Layer...
cd /d "%ROOT_DIR%\web-app"
call npm test
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Web Application tests failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [2/2] Testing Detection Engine API...
cd /d "%ROOT_DIR%\detection-engine"
if exist "venv\Scripts\python.exe" (
    .\venv\Scripts\python.exe -m unittest discover tests
) else if exist ".venv\Scripts\python.exe" (
    .\.venv\Scripts\python.exe -m unittest discover tests
) else (
    python -m unittest discover tests
)
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Detection Engine tests failed!
    exit /b %ERRORLEVEL%
)

echo.
echo =======================================================
echo   All automated tests PASSED successfully!
echo =======================================================
