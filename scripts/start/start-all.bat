@echo off
setlocal enabledelayedexpansion

:: 1. Determine Project Root Directory portably using %~dp0
pushd "%~dp0..\.."
set "ROOT_DIR=%CD%"
popd

echo =======================================================
echo   Starting SECURITY GUARD Services (Native Windows)
echo   Project Root: "%ROOT_DIR%"
echo =======================================================

:: 2. Prerequisite Checks
set "HAS_ERROR=0"

:: Check Node.js
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js is not installed or not in PATH!
    set "HAS_ERROR=1"
) else (
    for /f "tokens=*" %%v in ('node -v 2^>nul') do echo [OK] Node.js found: %%v
)

:: Check npm
where npm >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] npm is not installed or not in PATH!
    set "HAS_ERROR=1"
) else (
    for /f "tokens=*" %%v in ('npm -v 2^>nul') do echo [OK] npm found: %%v
)

:: Check Python and Detection Engine virtualenv
set "ACTIVATE_CMD="
if exist "%ROOT_DIR%\detection-engine\venv\Scripts\activate.bat" (
    set "ACTIVATE_CMD=call "%ROOT_DIR%\detection-engine\venv\Scripts\activate.bat""
    echo [OK] Detection Engine virtualenv: venv
) else if exist "%ROOT_DIR%\detection-engine\.venv\Scripts\activate.bat" (
    set "ACTIVATE_CMD=call "%ROOT_DIR%\detection-engine\.venv\Scripts\activate.bat""
    echo [OK] Detection Engine virtualenv: .venv
) else (
    where python >nul 2>&1
    if %ERRORLEVEL% EQU 0 (
        set "ACTIVATE_CMD=rem"
        echo [INFO] Using global Python interpreter
    ) else (
        echo [ERROR] Python is not installed and no virtualenv detected!
        set "HAS_ERROR=1"
    )
)

:: Check Web Application directory & node_modules
if not exist "%ROOT_DIR%\web-app\src\server.js" (
    echo [ERROR] Web Application entrypoint not found: "%ROOT_DIR%\web-app\src\server.js"
    set "HAS_ERROR=1"
)
if not exist "%ROOT_DIR%\web-app\node_modules" (
    echo [ERROR] Web Application dependencies missing: "%ROOT_DIR%\web-app\node_modules"
    echo         Please run scripts\setup\setup.bat first!
    set "HAS_ERROR=1"
)

:: Check Dashboard directory & node_modules
if not exist "%ROOT_DIR%\dashboard\package.json" (
    echo [ERROR] Dashboard directory not found: "%ROOT_DIR%\dashboard\package.json"
    set "HAS_ERROR=1"
)
if not exist "%ROOT_DIR%\dashboard\node_modules" (
    echo [ERROR] Dashboard dependencies missing: "%ROOT_DIR%\dashboard\node_modules"
    echo         Please run scripts\setup\setup.bat first!
    set "HAS_ERROR=1"
)

:: Check Detection Engine entrypoint
if not exist "%ROOT_DIR%\detection-engine\main.py" (
    echo [ERROR] Detection Engine entrypoint not found: "%ROOT_DIR%\detection-engine\main.py"
    set "HAS_ERROR=1"
)

:: Stop immediately if any prerequisite failed
if "!HAS_ERROR!"=="1" (
    echo.
    echo =======================================================
    echo [STARTUP ABORTED] Prerequisites check failed!
    echo No services were launched. Please resolve errors above.
    echo =======================================================
    exit /b 1
)

echo.
echo [Prerequisites OK] Launching services in separate windows...
echo.

:: 3. Launch Services in Separate Console Windows
:: Window 1: Detection Engine (Port 5000)
echo [1/6] Starting Detection Engine (Port 5000)...
start "SECURITY GUARD - Detection Engine" /D "%ROOT_DIR%\detection-engine" cmd /k "call venv\Scripts\activate.bat && python -m uvicorn main:app --host 0.0.0.0 --port 5000 --reload"

:: Window 2: Web Application (Port 3000)
echo [2/6] Starting Web Application (Port 3000)...
start "SECURITY GUARD - Web App" /D "%ROOT_DIR%\web-app" cmd /k "npm run dev"

:: Window 3: Dashboard (Port 5173)
echo [3/6] Starting Dashboard (Port 5173)...
start "SECURITY GUARD - Dashboard" /D "%ROOT_DIR%\dashboard" cmd /k "npm run dev"

:: Window 4: Monitoring Gateway (Port 8080) - Phase 10
echo [4/6] Starting Monitoring Gateway (Port 8080)...
start "SECURITY GUARD - Gateway" /D "%ROOT_DIR%\gateway" cmd /k "node server.js"

:: Window 5: Demo Node.js Website (Port 4001) - Phase 10
echo [5/6] Starting Demo Node.js Shop (Port 4001)...
start "SECURITY GUARD - Demo Node Shop" /D "%ROOT_DIR%\demo-sites\node-site" cmd /k "node server.js"

:: Window 6: Demo Python Website (Port 4002) - Phase 10
echo [6/6] Starting Demo Python Portal (Port 4002)...
start "SECURITY GUARD - Demo Python Portal" /D "%ROOT_DIR%\demo-sites\python-site" cmd /k "call ..\..\detection-engine\venv\Scripts\activate.bat && python server.py"

echo.
echo =======================================================
echo   All services launched in separate windows!
echo   Window 1: Detection Engine  -^> http://localhost:5000/docs
echo   Window 2: Web Application   -^> http://localhost:3000
echo   Window 3: Dashboard         -^> http://localhost:5173
echo   Window 4: Gateway (Proxy)   -^> http://localhost:8080
echo   Window 5: Demo Node Site    -^> http://localhost:4001
echo   Window 6: Demo Python Site  -^> http://localhost:4002
echo.
echo   Docker Security Labs (access via Gateway):
echo   - OWASP Juice Shop: http://localhost:8080/site/juiceshop/
echo   - DVWA:            http://localhost:8080/site/dvwa/
echo   - OWASP WebGoat:    http://localhost:8080/site/webgoat/WebGoat
echo   - OWASP WebWolf:    http://localhost:8080/site/webwolf/WebWolf
echo =======================================================
