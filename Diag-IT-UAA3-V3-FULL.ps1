<#
.SYNOPSIS
    Point d'entrée de compatibilité vers le moteur canonique DiagToolIT.
.DESCRIPTION
    Ce fichier conserve l'ancien nom distribué sans dupliquer le moteur principal.
#>

[CmdletBinding()]
param (
    [switch]$NoElevate,

    [ValidateSet('FR', 'NL', 'EN', 'DE')]
    [string]$Lang = 'FR',

    [ValidateScript({ $_ -notmatch '"' })]
    [string]$OutputPath,

    [switch]$NoHistory,

    [switch]$NoOpen,

    [switch]$NonInteractive
)

$mainScript = Join-Path $PSScriptRoot 'Diag-IT-UAA3-V3.ps1'
if (-not (Test-Path -LiteralPath $mainScript)) {
    throw "Moteur DiagToolIT introuvable : $mainScript"
}

$forwardParameters = @{
    Lang = $Lang
}
if ($NoElevate) {
    $forwardParameters.NoElevate = $true
}
if ($PSBoundParameters.ContainsKey('OutputPath')) {
    $forwardParameters.OutputPath = $OutputPath
}
if ($NoHistory) { $forwardParameters.NoHistory = $true }
if ($NoOpen) { $forwardParameters.NoOpen = $true }
if ($NonInteractive) { $forwardParameters.NonInteractive = $true }

& $mainScript @forwardParameters
