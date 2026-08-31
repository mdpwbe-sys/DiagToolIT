function Get-DiagSmartMetric {
    param(
        [object]$ReliabilityCounter,
        [Parameter(Mandatory)]
        [string]$PropertyName
    )

    if ($null -eq $ReliabilityCounter) {
        return '—'
    }

    $property = $ReliabilityCounter.PSObject.Properties[$PropertyName]
    if ($null -eq $property -or $null -eq $property.Value -or
        [string]::IsNullOrWhiteSpace([string]$property.Value)) {
        return '—'
    }

    return $property.Value
}

function Get-DiagSmartModelName {
    param(
        [Parameter(Mandatory)]
        [object]$PhysicalDisk,
        [object]$DiskMetadata
    )

    $candidates = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in @(
        $PhysicalDisk.FriendlyName
        $PhysicalDisk.Model
        if ($DiskMetadata) { $DiskMetadata.FriendlyName }
        if ($DiskMetadata) { $DiskMetadata.Model }
        if ($DiskMetadata) { $DiskMetadata.SerialNumber }
        if ($PhysicalDisk.SerialNumber) { $PhysicalDisk.SerialNumber }
        if ($null -ne $PhysicalDisk.DeviceId) { "Disque physique $($PhysicalDisk.DeviceId)" }
    )) {
        if (-not [string]::IsNullOrWhiteSpace([string]$candidate)) {
            $candidates.Add([string]$candidate)
        }
    }

    if ($candidates.Count -gt 0) {
        return $candidates[0]
    }
    return 'Disque physique'
}

function ConvertTo-DiagSmartTelemetryRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object]$PhysicalDisk,
        [object]$ReliabilityCounter,
        [object]$DiskMetadata
    )

    $unavailable = '—'
    $sizeBytes = if ($null -ne $PhysicalDisk.Size) { [double]$PhysicalDisk.Size } else { 0 }
    $mediaType = if (-not [string]::IsNullOrWhiteSpace([string]$PhysicalDisk.MediaType)) {
        [string]$PhysicalDisk.MediaType
    } else {
        'Inconnu'
    }
    $health = if (-not [string]::IsNullOrWhiteSpace([string]$PhysicalDisk.HealthStatus)) {
        [string]$PhysicalDisk.HealthStatus
    } else {
        'Inconnu'
    }

    $wear = Get-DiagSmartMetric -ReliabilityCounter $ReliabilityCounter -PropertyName 'Wear'
    $powerOnHours = Get-DiagSmartMetric -ReliabilityCounter $ReliabilityCounter -PropertyName 'PowerOnHours'
    $temperature = Get-DiagSmartMetric -ReliabilityCounter $ReliabilityCounter -PropertyName 'Temperature'
    $readErrors = Get-DiagSmartMetric -ReliabilityCounter $ReliabilityCounter -PropertyName 'ReadErrorsTotal'

    [PSCustomObject]@{
        Model = Get-DiagSmartModelName -PhysicalDisk $PhysicalDisk -DiskMetadata $DiskMetadata
        MediaType = $mediaType
        SizeGB = [math]::Round($sizeBytes / 1GB, 1)
        Health = $health
        WearPct = if ($wear -eq $unavailable) { $unavailable } else { [int]$wear }
        PowerOnHours = if ($powerOnHours -eq $unavailable) { $unavailable } else { [int64]$powerOnHours }
        Temperature = if ($temperature -eq $unavailable) { $unavailable } else { "$temperature °C" }
        ReadErrors = if ($readErrors -eq $unavailable) { $unavailable } else { [int64]$readErrors }
    }
}
