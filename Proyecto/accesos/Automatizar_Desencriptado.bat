@echo off
setlocal
cd /d "%~dp0.."
set "PYTHONPATH=%CD%\src"
"..\venv\Scripts\python.exe" scripts\auto_gui.py
if errorlevel 1 (
    echo No se pudo completar la operacion.
    pause
    exit /b 1
)
exit /b 0
