@echo off
setlocal
chcp 65001 >nul
title Diag-IT UAA3 Enterprise // Multilingual Suite
cd /d "%~dp0"

:: Le moteur PowerShell gere lui-meme l'elevation UAC.

echo ==========================================================================
echo       DIAG-IT UAA3 // CENTRE DE DIAGNOSTIC ET GESTION IT
echo ==========================================================================
echo.
echo   Choisissez votre langue / Kies uw taal / Select language / Sprache:
echo.
echo     [1] Francais
echo     [2] Nederlands
echo     [3] English
echo     [4] Deutsch
echo.
echo ==========================================================================
choice /c 1234 /n /m "Selectionnez votre option [1, 2, 3, 4] : "
set "CHOICE_EXIT=%errorlevel%"

if "%CHOICE_EXIT%"=="4" goto LANG_DE
if "%CHOICE_EXIT%"=="3" goto LANG_EN
if "%CHOICE_EXIT%"=="2" goto LANG_NL
if "%CHOICE_EXIT%"=="1" goto LANG_FR

echo.
echo [ERREUR] Impossible de lire le choix de langue.
pause
endlocal
exit /b 1

:LANG_DE
set "DIAG_LANG=DE"
goto RUN_DIAG

:LANG_EN
set "DIAG_LANG=EN"
goto RUN_DIAG

:LANG_NL
set "DIAG_LANG=NL"
goto RUN_DIAG

:LANG_FR
set "DIAG_LANG=FR"
goto RUN_DIAG

:RUN_DIAG
if /I "%DIAG_LANG%"=="FR" goto REGISTER_FR
if /I "%DIAG_LANG%"=="NL" goto REGISTER_NL
if /I "%DIAG_LANG%"=="EN" goto REGISTER_EN
if /I "%DIAG_LANG%"=="DE" goto REGISTER_DE
goto REGISTER_INVALID

:REGISTER_FR
set "REGISTER_MSG=Enregistrement des raccourcis systeme diagit:// et diagit-cve:// pour le dashboard..."
set "REGISTER_FAIL=Impossible d'enregistrer les raccourcis systeme ; le diagnostic continue."
goto REGISTER_PROTOCOL

:REGISTER_NL
set "REGISTER_MSG=De systeemkoppelingen diagit:// en diagit-cve:// voor het dashboard registreren..."
set "REGISTER_FAIL=De systeemkoppelingen konden niet worden geregistreerd; de diagnose gaat door."
goto REGISTER_PROTOCOL

:REGISTER_EN
set "REGISTER_MSG=Registering the diagit:// and diagit-cve:// dashboard system shortcuts..."
set "REGISTER_FAIL=Unable to register the system shortcuts; the diagnostic will continue."
goto REGISTER_PROTOCOL

:REGISTER_DE
set "REGISTER_MSG=Die diagit://- und diagit-cve://-Systemverknuepfungen fuer das Dashboard werden registriert..."
set "REGISTER_FAIL=Die Systemverknuepfungen konnten nicht registriert werden; die Diagnose wird fortgesetzt."
goto REGISTER_PROTOCOL

:REGISTER_INVALID
set "REGISTER_MSG=Registering dashboard system shortcuts..."
set "REGISTER_FAIL=Unable to select a valid language for protocol registration; the diagnostic will continue."

:REGISTER_PROTOCOL

echo.
echo %REGISTER_MSG%
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Register-DiagProtocol.ps1" -Quiet
set "REGISTER_EXIT=%errorlevel%"
if not "%REGISTER_EXIT%"=="0" echo [WARNING] %REGISTER_FAIL%

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Diag-IT-UAA3-V3.ps1" -Lang %DIAG_LANG%
set "DIAG_EXIT=%errorlevel%"

if "%DIAG_EXIT%"=="0" goto DIAG_DONE
echo.
echo [ERREUR] DiagToolIT s'est arrete avec le code %DIAG_EXIT%.
echo Consultez le message PowerShell ci-dessus avant de fermer cette fenetre.
pause

:DIAG_DONE

endlocal & exit /b %DIAG_EXIT%
