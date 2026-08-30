<#
.SYNOPSIS
    Enregistre le protocole d'URL Windows diagit:// pour permettre le lancement 1-clic depuis le navigateur (Opera, Chrome, Edge).
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$PassThru
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$MainScript = Join-Path $ScriptDir 'Diag-IT-UAA3-V3.ps1'
$CveUpdateScript = Join-Path $ScriptDir 'Update-CveDatabase.ps1'
foreach ($requiredFile in @($MainScript, $CveUpdateScript)) {
    if (-not (Test-Path -LiteralPath $requiredFile -PathType Leaf)) {
        throw "Fichier DiagToolIT introuvable : $requiredFile"
    }
}

$protocolDefinitions = @(
    [PSCustomObject]@{
        Scheme      = 'diagit'
        Description = 'URL:DiagToolIT One-Click Diagnostic Protocol'
        Command     = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$MainScript`""
    },
    [PSCustomObject]@{
        Scheme      = 'diagit-cve'
        Description = 'URL:DiagToolIT Explicit CVE Update Protocol'
        Command     = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$CveUpdateScript`" -Interactive"
    }
)

try {
    foreach ($definition in $protocolDefinitions) {
        $protocolPath = "HKCU:\Software\Classes\$($definition.Scheme)"
        $commandPath = Join-Path $protocolPath 'shell\open\command'
        if ($PSCmdlet.ShouldProcess($protocolPath, "Enregistrer le protocole $($definition.Scheme)://")) {
            New-Item -Path $protocolPath -Force | Out-Null
            Set-ItemProperty -Path $protocolPath -Name '(default)' -Value $definition.Description
            Set-ItemProperty -Path $protocolPath -Name 'URL Protocol' -Value ''
            New-Item -Path $commandPath -Force | Out-Null
            Set-ItemProperty -Path $commandPath -Name '(default)' -Value $definition.Command
            Write-Host "[OK] Protocole $($definition.Scheme):// enregistré pour l'utilisateur courant." -ForegroundColor Green
        }
    }
} catch {
    throw "Impossible d'enregistrer les protocoles DiagToolIT : $($_.Exception.Message)"
}

if ($PassThru) {
    $protocolDefinitions
}
