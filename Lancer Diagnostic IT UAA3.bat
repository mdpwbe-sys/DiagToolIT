@echo off
chcp 65001 >nul
title Diag-IT UAA3 Enterprise // Multilingual Suite
cd /d "%~dp0"

:: Auto-Elevation UAC Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Demande des droits Administrateur (UAC)...
    powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Start-Process cmd.exe -ArgumentList '/c ""%~f0""' -Verb RunAs"
    exit /b
)

echo ==========================================================================
echo       🛠️  DIAG-IT UAA3 // CENTRE DE DIAGNOSTIC ET GESTION IT
echo ==========================================================================
echo.
echo   Choisissez votre langue / Kies uw taal / Select language / Sprache:
echo.
echo     [1] Français
echo     [2] Nederlands
echo     [3] English
echo     [4] Deutsch
echo.
echo ==========================================================================
choice /c 1234 /n /m "Sélectionnez votre option [1, 2, 3, 4] : "

if errorlevel 4 goto LANG_DE
if errorlevel 3 goto LANG_EN
if errorlevel 2 goto LANG_NL
if errorlevel 1 goto LANG_FR

:LANG_FR
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1" -Lang FR
goto END

:LANG_NL
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1" -Lang NL
goto END

:LANG_EN
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1" -Lang EN
goto END

:LANG_DE
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1" -Lang DE
goto END

:END
