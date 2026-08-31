function ConvertFrom-DiagAntivirusProductState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [uint32]$ProductState
    )

    $stateByte = [int](($ProductState -shr 8) -band 0xFF)
    $signatureByte = [int]($ProductState -band 0xFF)
    $stateFamily = $stateByte -band 0xF0

    $state = switch ($stateFamily) {
        0x10 { 'On'; break }
        0x20 { 'Snoozed'; break }
        0x30 { 'Expired'; break }
        default { 'Off' }
    }

    [PSCustomObject]@{
        RawProductState  = $ProductState
        HexProductState  = ('0x{0:X6}' -f $ProductState)
        StateByte        = $stateByte
        SignatureByte    = $signatureByte
        State            = $state
        IsActive         = ($state -eq 'On')
        SignaturesCurrent = (($signatureByte -band 0x10) -eq 0)
    }
}

function Test-DiagMicrosoftDefenderProvider {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$Product
    )

    $identity = @(
        $Product.displayName
        $Product.pathToSignedProductExe
        $Product.pathToSignedReportingExe
    ) -join ' '

    return $identity -match '(?i)(?:microsoft|windows)\s+defender|msmpeng\.exe'
}

function Get-DiagAntivirusAssessment {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$DefenderStatus,

        [AllowNull()]
        [object[]]$SecurityCenterProducts = @()
    )

    $activeProducts = [System.Collections.Generic.List[string]]::new()
    $inactiveProducts = [System.Collections.Generic.List[string]]::new()
    $outdatedProducts = [System.Collections.Generic.List[string]]::new()

    $defenderMode = if ($null -ne $DefenderStatus -and $DefenderStatus.PSObject.Properties.Name -contains 'AMRunningMode') {
        [string]$DefenderStatus.AMRunningMode
    } else {
        ''
    }
    $defenderActive = $null -ne $DefenderStatus -and
        $DefenderStatus.AMServiceEnabled -eq $true -and
        $DefenderStatus.AntivirusEnabled -eq $true -and
        $DefenderStatus.RealTimeProtectionEnabled -eq $true -and
        $defenderMode -notmatch '(?i)passive|edr\s+blocked|disabled'

    if ($defenderActive) {
        $activeProducts.Add('Microsoft Defender')
        if ($DefenderStatus.PSObject.Properties.Name -contains 'DefenderSignaturesOutOfDate' -and
            $DefenderStatus.DefenderSignaturesOutOfDate -eq $true) {
            $outdatedProducts.Add('Microsoft Defender')
        }
    } else {
        $inactiveProducts.Add('Microsoft Defender')
    }

    foreach ($product in @($SecurityCenterProducts)) {
        if ($null -eq $product -or (Test-DiagMicrosoftDefenderProvider -Product $product)) {
            continue
        }

        $productName = if ([string]::IsNullOrWhiteSpace([string]$product.displayName)) {
            'Unknown third-party antivirus'
        } else {
            [string]$product.displayName
        }

        $decodedState = $null
        if ($null -ne $product.productState) {
            try {
                $decodedState = ConvertFrom-DiagAntivirusProductState -ProductState ([uint32]$product.productState)
            } catch {
                $decodedState = $null
            }
        }

        if ($decodedState -and $decodedState.IsActive) {
            $activeProducts.Add($productName)
            if (-not $decodedState.SignaturesCurrent) {
                $outdatedProducts.Add($productName)
            }
        } else {
            $inactiveProducts.Add($productName)
        }
    }

    $status = 'OK'
    $reason = 'Protected'
    if ($activeProducts.Count -eq 0) {
        $status = 'ERROR'
        $reason = 'NoActiveProtection'
    } elseif ($activeProducts.Count -gt 1) {
        $status = 'WARNING'
        $reason = 'MultipleActiveProducts'
    } elseif ($outdatedProducts.Count -gt 0) {
        $status = 'WARNING'
        $reason = 'SignaturesOutOfDate'
    }

    [PSCustomObject]@{
        Status           = $status
        Reason           = $reason
        DefenderActive   = $defenderActive
        ActiveProducts   = @($activeProducts)
        InactiveProducts = @($inactiveProducts)
        OutdatedProducts = @($outdatedProducts)
    }
}
