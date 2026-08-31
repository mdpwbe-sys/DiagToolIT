$projectRoot = Split-Path -Parent $PSScriptRoot
$antivirusScript = Join-Path $projectRoot 'Diag-Antivirus.ps1'

Describe 'DiagToolIT antivirus assessment' {
    BeforeAll {
        if (-not (Test-Path -LiteralPath $antivirusScript -PathType Leaf)) {
            throw "Missing antivirus assessment seam: $antivirusScript"
        }
        . $antivirusScript
    }

    function New-DefenderStatus {
        param([bool]$Enabled)

        [PSCustomObject]@{
            AMServiceEnabled             = $Enabled
            AntivirusEnabled             = $Enabled
            RealTimeProtectionEnabled    = $Enabled
            DefenderSignaturesOutOfDate  = $false
        }
    }

    function New-SecurityCenterProduct {
        param(
            [string]$Name,
            [uint32]$ProductState
        )

        [PSCustomObject]@{
            displayName                  = $Name
            productState                 = $ProductState
            pathToSignedProductExe       = ''
            pathToSignedReportingExe     = ''
        }
    }

    It 'reports an error when Defender is disabled even if its stale provider is present' {
        $assessment = Get-DiagAntivirusAssessment `
            -DefenderStatus (New-DefenderStatus $false) `
            -SecurityCenterProducts @(
                (New-SecurityCenterProduct 'Microsoft Defender Antivirus' 397568)
            )

        if ($assessment.Status -ne 'ERROR') {
            throw "Expected ERROR, got $($assessment.Status): $($assessment.Reason)"
        }
        if ($assessment.Reason -ne 'NoActiveProtection') {
            throw "Expected NoActiveProtection, got $($assessment.Reason)"
        }
    }

    It 'reports OK when Get-MpComputerStatus says Defender is active' {
        $assessment = Get-DiagAntivirusAssessment `
            -DefenderStatus (New-DefenderStatus $true) `
            -SecurityCenterProducts @(
                (New-SecurityCenterProduct 'Windows Defender' 393472)
            )

        if ($assessment.Status -ne 'OK') {
            throw "Expected OK, got $($assessment.Status): $($assessment.Reason)"
        }
        if ($assessment.ActiveProducts -notcontains 'Microsoft Defender') {
            throw 'The active Defender authority result was not retained.'
        }
    }

    It 'does not treat passive Defender as active protection' {
        $status = New-DefenderStatus $true
        $status | Add-Member -NotePropertyName AMRunningMode -NotePropertyValue 'Passive'
        $assessment = Get-DiagAntivirusAssessment -DefenderStatus $status -SecurityCenterProducts @()

        if ($assessment.Status -ne 'ERROR') {
            throw "Expected ERROR for passive Defender, got $($assessment.Status): $($assessment.Reason)"
        }
    }

    It 'reports OK for an active and current third-party antivirus' {
        $assessment = Get-DiagAntivirusAssessment `
            -DefenderStatus (New-DefenderStatus $false) `
            -SecurityCenterProducts @(
                (New-SecurityCenterProduct 'Contoso Endpoint Security' 397568)
            )

        if ($assessment.Status -ne 'OK') {
            throw "Expected OK, got $($assessment.Status): $($assessment.Reason)"
        }
        if ($assessment.ActiveProducts -notcontains 'Contoso Endpoint Security') {
            throw 'The active third-party provider was not retained.'
        }
    }

    It 'does not treat an inactive third-party provider as protection' {
        $assessment = Get-DiagAntivirusAssessment `
            -DefenderStatus (New-DefenderStatus $false) `
            -SecurityCenterProducts @(
                (New-SecurityCenterProduct 'Contoso Endpoint Security' 393472)
            )

        if ($assessment.Status -ne 'ERROR') {
            throw "Expected ERROR, got $($assessment.Status): $($assessment.Reason)"
        }
    }

    It 'warns when the only active third-party provider has stale signatures' {
        $assessment = Get-DiagAntivirusAssessment `
            -DefenderStatus (New-DefenderStatus $false) `
            -SecurityCenterProducts @(
                (New-SecurityCenterProduct 'Contoso Endpoint Security' 397584)
            )

        if ($assessment.Status -ne 'WARNING') {
            throw "Expected WARNING, got $($assessment.Status): $($assessment.Reason)"
        }
        if ($assessment.Reason -ne 'SignaturesOutOfDate') {
            throw "Expected SignaturesOutOfDate, got $($assessment.Reason)"
        }
    }
}
