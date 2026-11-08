@echo off
setlocal
cd /d "%~dp0.."
set "PYTHONPATH=%CD%\src"
"..\venv\Scripts\python.exe" scripts\auto_watcher.py stop
if errorlevel 1 (
    echo No se pudo completar la operacion.
    pause
    exit /b 1
)
timeout /t 3 /nobreak >nul 2>&1
exit /b 0
