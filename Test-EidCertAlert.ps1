<#
.SYNOPSIS
    Test et validation de l'alerte d'expiration a 30 jours pour les certificats numeriques eID.
.DESCRIPTION
    Scanne les magasins de certificats locaux et verifie la detection des certificats expirant
    sous 30 jours conformement aux exigences du Module 5.
#>

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'SilentlyContinue'

Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host "   AUDIT TEST : EXPIRATION DES CERTIFICATS NUMERIQUES ET eID             " -ForegroundColor Cyan
Write-Host "==========================================================================" -ForegroundColor Cyan
Write-Host ""

$certStores = @("Cert:\CurrentUser\My", "Cert:\LocalMachine\My")
$totalFound = 0
$expiringSoon = 0

foreach ($store in $certStores) {
    Write-Host "Magasin : $store" -ForegroundColor Yellow
    if (Test-Path $store) {
        $certs = Get-ChildItem -Path $store -ErrorAction SilentlyContinue
        foreach ($c in $certs) {
            $totalFound++
            $daysLeft = [math]::Round(($c.NotAfter - (Get-Date)).TotalDays)
            $isEid = ($c.Subject -match "Citizen|BELGIUM|Belgium" -or $c.Issuer -match "Citizen|Belgium")
            
            $statusText = if ($daysLeft -lt 0) {
                "[EXPIRE]"
            } elseif ($daysLeft -le 30) {
                $expiringSoon++
                "[ALERTE EXPIRATION SOUS $daysLeft JOURS]"
            } else {
                "[VALIDE : $daysLeft jours]"
            }

            $color = if ($daysLeft -lt 0) { "Red" } elseif ($daysLeft -le 30) { "Yellow" } else { "Green" }
            Write-Host "  * $($c.Subject)" -ForegroundColor White
            Write-Host "    -> $statusText (NotAfter: $($c.NotAfter.ToString('dd/MM/yyyy')))" -ForegroundColor $color
            if ($isEid) {
                Write-Host "    -> [eID Belgium Matcher Actif]" -ForegroundColor Cyan
            }
        }
    }
}

Write-Host ""
Write-Host "Bilan : $totalFound certificats audites, $expiringSoon certificat(s) expirant sous 30 jours." -ForegroundColor Gray
Write-Host "==========================================================================" -ForegroundColor Cyan
