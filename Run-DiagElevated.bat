@echo off
setlocal
cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1"
endlocal
exit /b
