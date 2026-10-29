@echo off
setlocal
pushd "%~dp0.."
set "ROOT_DIR=%CD%"
popd

echo =======================================================
echo   Training Isolation Forest ML Anomaly Model (Phase 6)
echo   Project Root: "%ROOT_DIR%"
echo =======================================================

cd /d "%ROOT_DIR%\detection-engine"
if exist "venv\Scripts\python.exe" (
    .\venv\Scripts\python.exe -m ml.train
    .\venv\Scripts\python.exe -m ml.evaluate
) else if exist ".venv\Scripts\python.exe" (
    .\.venv\Scripts\python.exe -m ml.train
    .\.venv\Scripts\python.exe -m ml.evaluate
) else (
    python -m ml.train
    python -m ml.evaluate
)
