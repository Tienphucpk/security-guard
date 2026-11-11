@echo off
setlocal

echo =======================================================
echo   Stopping SECURITY GUARD Services
echo =======================================================

echo [1/3] Terminating service processes by listening ports...

:: Port 3000 (Web Application)
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":3000 " ^| findstr "LISTENING"') do (
    if not "%%p"=="" (
        echo Stopping Web App process on port 3000 - PID %%p
        taskkill /F /T /PID %%p >nul 2>&1
    )
)

:: Port 5000 (Detection Engine)
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":5000 " ^| findstr "LISTENING"') do (
    if not "%%p"=="" (
        echo Stopping Detection Engine process on port 5000 - PID %%p
        taskkill /F /T /PID %%p >nul 2>&1
    )
)

:: Port 5173 (Dashboard)
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":5173 " ^| findstr "LISTENING"') do (
    if not "%%p"=="" (
        echo Stopping Dashboard process on port 5173 - PID %%p
        taskkill /F /T /PID %%p >nul 2>&1
    )
)

:: Port 8080 (Gateway - Phase 10)
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":8080 " ^| findstr "LISTENING"') do (
    if not "%%p"=="" (
        echo Stopping Gateway process on port 8080 - PID %%p
        taskkill /F /T /PID %%p >nul 2>&1
    )
)

:: Port 4001 (Demo Node Shop - Phase 10)
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":4001 " ^| findstr "LISTENING"') do (
    if not "%%p"=="" (
        echo Stopping Demo Node Shop process on port 4001 - PID %%p
        taskkill /F /T /PID %%p >nul 2>&1
    )
)

:: Port 4002 (Demo Python Portal - Phase 10)
for /f "tokens=5" %%p in ('netstat -aon 2^>nul ^| findstr ":4002 " ^| findstr "LISTENING"') do (
    if not "%%p"=="" (
        echo Stopping Demo Python Portal process on port 4002 - PID %%p
        taskkill /F /T /PID %%p >nul 2>&1
    )
)

echo [2/3] Closing SECURITY GUARD console windows and child workers...
taskkill /F /T /FI "WINDOWTITLE eq SECURITY GUARD - Detection Engine*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SECURITY GUARD - Web App*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SECURITY GUARD - Dashboard*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SECURITY GUARD - Gateway*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SECURITY GUARD - Demo Node Shop*" >nul 2>&1
taskkill /F /T /FI "WINDOWTITLE eq SECURITY GUARD - Demo Python Portal*" >nul 2>&1

:: Clean up any lingering reload workers
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { ($_.CommandLine -like '*uvicorn main:app*') -or ($_.CommandLine -like '*node --watch src/server.js*') -or ($_.CommandLine -like '*node*vite.js*') } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }" >nul 2>&1

echo [3/3] Preserving active Docker lab containers (Juice Shop, DVWA, WebGoat).

echo.
echo =======================================================
echo   All SECURITY GUARD services stopped!
echo =======================================================
