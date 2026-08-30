<#
.SYNOPSIS
    Enregistre le protocole d'URL Windows diagit:// pour permettre le lancement 1-clic depuis le navigateur (Opera, Chrome, Edge).
#>
[CmdletBinding()]
param()

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainScript = Join-Path $ScriptDir "Diag-IT-UAA3-V3.ps1"
if (-not (Test-Path $MainScript)) {
    throw "Moteur DiagToolIT introuvable : $MainScript"
}

$ProtocolCommand = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$MainScript`""

try {
    # Clé principale du protocole
    New-Item -Path "HKCU:\Software\Classes\diagit" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\diagit" -Name "(default)" -Value "URL:DiagToolIT One-Click Protocol"
    Set-ItemProperty -Path "HKCU:\Software\Classes\diagit" -Name "URL Protocol" -Value ""
    
    # Commande d'exécution
    New-Item -Path "HKCU:\Software\Classes\diagit\shell\open\command" -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Classes\diagit\shell\open\command" -Name "(default)" -Value $ProtocolCommand
    
    Write-Host "[OK] Protocole diagit:// enregistré avec succès pour l'utilisateur courant !" -ForegroundColor Green
} catch {
    Write-Host "[ERREUR] Impossible d'enregistrer le protocole : $_" -ForegroundColor Red
}
