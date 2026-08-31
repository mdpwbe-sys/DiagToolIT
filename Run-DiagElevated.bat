@echo off
setlocal
cd /d "%~dp0"

set "DIAG_LANG="
if "%~1"=="FR" set "DIAG_LANG=FR"
if "%~1"=="NL" set "DIAG_LANG=NL"
if "%~1"=="EN" set "DIAG_LANG=EN"
if "%~1"=="DE" set "DIAG_LANG=DE"

if not defined DIAG_LANG (
    echo [ERROR] Invalid diagnostic language. Expected FR, NL, EN, or DE.
    endlocal
    exit /b 2
)

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1" -Lang %DIAG_LANG%
set "DIAG_EXIT=%errorlevel%"
endlocal & exit /b %DIAG_EXIT%
