<#>
.SYNOPSIS
    Chargeur de configuration DiagToolIT (modules_config.json).
.DESCRIPTION
    Lit et valide modules_config.json de façon stricte (ConvertFrom-Json), vérifie les
    sections/propriétés requises, et fournit un repli sûr sur des valeurs par défaut si
    le fichier est absent, invalide ou partiel. Aucune donnée machine ne transit ici.
    Ce fichier ne fait qu'exposer la fonction Get-DiagConfig ; il n'exécute aucun diagnostic.
#>
[CmdletBinding()]
param()

function Get-DiagConfig {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ConfigPath
    )

    # Repli sûr (valeurs par défaut = comportement actuel du moteur avant intégration)
    $defaults = [PSCustomObject]@{
        history = [PSCustomObject]@{
            max_runs_retention     = 120
            max_days_retention      = 90
            score_baseline_threshold = 75
        }
        cve_scanner = [PSCustomObject]@{
            cvss_min_severity = 7.0
        }
        belgian_ecosystem = [PSCustomObject]@{
            cert_alert_days         = 30
            cert_critical_alert_days = 7
        }
    }

    if (-not (Test-Path -LiteralPath $ConfigPath)) {
        throw "modules_config.json introuvable : $ConfigPath. Repli sur les valeurs par defaut."
    }

    $raw = $null
    try {
        $raw = Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "modules_config.json invalide (JSON illisible) : $($_.Exception.Message). Repli sur les valeurs par defaut."
    }

    if (-not $raw -or -not $raw.settings) {
        throw "modules_config.json sans section 'settings'. Repli sur les valeurs par defaut."
    }

    $s = $raw.settings

    # Récupère une valeur ou le défaut ; vérifie le type numérique positif quand pertinent
    function Get-Val {
        param($Section, $Key, $Default)
        if ($Section -and $Section.PSObject.Properties[$Key]) {
            $v = $Section.$Key
            # Les seuils numériques doivent être des nombres > 0, sinon défaut
            if ($v -is [double] -or $v -is [int] -or $v -is [long] -or $v -is [decimal]) {
                if ([double]$v -le 0) { return $Default }
            }
            return $v
        }
        return $Default
    }

    $merged = [PSCustomObject]@{
        history = [PSCustomObject]@{
            max_runs_retention      = [int](Get-Val $s.history 'max_runs_retention' $defaults.history.max_runs_retention)
            max_days_retention      = [int](Get-Val $s.history 'max_days_retention' $defaults.history.max_days_retention)
            score_baseline_threshold = [int](Get-Val $s.history 'score_baseline_threshold' $defaults.history.score_baseline_threshold)
        }
        cve_scanner = [PSCustomObject]@{
            cvss_min_severity = [double](Get-Val $s.cve_scanner 'cvss_min_severity' $defaults.cve_scanner.cvss_min_severity)
        }
        belgian_ecosystem = [PSCustomObject]@{
            cert_alert_days          = [int](Get-Val $s.belgian_ecosystem 'cert_alert_days' $defaults.belgian_ecosystem.cert_alert_days)
            cert_critical_alert_days = [int](Get-Val $s.belgian_ecosystem 'cert_critical_alert_days' $defaults.belgian_ecosystem.cert_critical_alert_days)
        }
    }

    return $merged
}
