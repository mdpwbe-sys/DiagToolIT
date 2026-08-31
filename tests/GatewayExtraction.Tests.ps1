$projectRoot = Split-Path -Parent $PSScriptRoot

Describe 'DiagToolIT gateway IPv4 extraction (regression)' {
    # Reproduces the exact extraction logic used in Diag-IT-UAA3-V3.ps1 line 204:
    #   $gwList = @($ipProps.GatewayAddresses | Where-Object { ... } | ForEach-Object { $_.Address.IPAddressToString })
    # The bug: when there is exactly ONE gateway, the value is a scalar string and
    # $gwList[0] returns the first CHARACTER ('1' instead of '192.168.129.1').
    # We wrap it in a function to expose the real failure mode (PowerShell unrolls a
    # single-element array on return), and the leading comma in `return ,$result`
    # prevents that unrolling -- mirroring what the in-scope @(...) assignment does.
    function Get-GatewayList {
        param($gatewayAddresses)

        $result = @(
            $gatewayAddresses |
                Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.Address.IPAddressToString }
        )

        return ,$result
    }

    function New-GwAddr($ip) {
        [PSCustomObject]@{ Address = [PSCustomObject]@{ AddressFamily = 'InterNetwork'; IPAddressToString = $ip } }
    }

    It 'returns an empty list (null-safe) when there is no gateway' {
        $gw = Get-GatewayList -gatewayAddresses @()
        if ($gw -isnot [System.Array]) { throw "Expected an array, got $($gw.GetType().Name)" }
        if ($gw.Count -ne 0) { throw "Expected 0 gateways, got $($gw.Count)" }
        $reported = if ($gw) { $gw[0] } else { $null }
        if ($null -ne $reported) { throw "Expected null gateway report, got '$reported'" }
    }

    It 'returns the FULL address when there is exactly one gateway (regression for the ''1'' bug)' {
        $gw = Get-GatewayList -gatewayAddresses @( (New-GwAddr '192.168.129.1') )
        if ($gw -isnot [System.Array]) { throw "Expected an array, got $($gw.GetType().Name)" }
        if ($gw.Count -ne 1) { throw "Expected 1 gateway, got $($gw.Count)" }
        if ($gw[0] -ne '192.168.129.1') { throw "Bug reproduced: gateway extracted as '$($gw[0])' instead of '192.168.129.1'" }
    }

    It 'returns all full addresses when there are several gateways' {
        $addrs = @( (New-GwAddr '10.0.0.1'), (New-GwAddr '10.0.0.254') )
        $gw = Get-GatewayList -gatewayAddresses $addrs
        if ($gw -isnot [System.Array]) { throw "Expected an array, got $($gw.GetType().Name)" }
        if ($gw.Count -ne 2) { throw "Expected 2 gateways, got $($gw.Count)" }
        if ($gw[0] -ne '10.0.0.1') { throw "First gateway wrong: '$($gw[0])'" }
        if ($gw[1] -ne '10.0.0.254') { throw "Second gateway wrong: '$($gw[1])'" }
    }

    It 'keeps configured IPv4 DNS servers in the adapter details' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        $wrongPattern = '\$ipProps\.DnsAddresses\s*\|\s*Where-Object\s*\{\s*\$_.Address\.AddressFamily'
        if ([regex]::Matches($source, $wrongPattern).Count -gt 0) {
            throw 'DNS extraction still treats IPAddress entries as objects with an Address property.'
        }

        $correctPattern = '\$ipProps\.DnsAddresses\s*\|\s*Where-Object\s*\{\s*\$_.AddressFamily\s*-eq\s*''InterNetwork''\s*\}\s*\|\s*ForEach-Object\s*\{\s*\$_.IPAddressToString'
        if ([regex]::Matches($source, $correctPattern).Count -lt 2) {
            throw 'Both adapter DNS extraction paths must filter IPAddress.AddressFamily and emit IPAddressToString.'
        }
    }
}
