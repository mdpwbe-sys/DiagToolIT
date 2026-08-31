function ConvertTo-DiagGpuMemoryBytes {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return [UInt64]0 }
    if ($Value -is [byte[]]) {
        try {
            if ($Value.Length -ge 8) { return [BitConverter]::ToUInt64($Value, 0) }
            if ($Value.Length -ge 4) { return [UInt64]([BitConverter]::ToUInt32($Value, 0)) }
        } catch { return [UInt64]0 }
    }
    try { return [UInt64]$Value } catch { return [UInt64]0 }
}

function ConvertTo-DiagGpuMemoryGB {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$AdapterRamBytes,

        [AllowNull()]
        [object]$RegistryMemoryBytes
    )

    $adapterBytes = ConvertTo-DiagGpuMemoryBytes -Value $AdapterRamBytes
    $registryBytes = ConvertTo-DiagGpuMemoryBytes -Value $RegistryMemoryBytes

    # Win32_VideoController.AdapterRAM is uint32 and wraps high-VRAM cards near 4 GB.
    $selectedBytes = if ($registryBytes -gt $adapterBytes -and $registryBytes -ge 1GB) {
        $registryBytes
    } else {
        $adapterBytes
    }
    if ($selectedBytes -le 0) { return [double]0 }
    return [math]::Round(([double]$selectedBytes / 1GB), 1)
}
