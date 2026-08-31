$projectRoot = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $projectRoot 'Diag-SmartTelemetry.ps1'
. $modulePath

Describe 'DiagToolIT SMART telemetry' {
    It 'keeps the physical model name and distinguishes unavailable counters from zero' {
        $disk = [pscustomobject]@{
            FriendlyName = ''
            Model = ''
            DeviceId = 3
            MediaType = 'SSD'
            Size = 1000GB
            HealthStatus = 'Healthy'
        }
        $metadata = [pscustomobject]@{
            FriendlyName = 'CT1000P3SSD8'
            SerialNumber = 'SN-REDACTED'
        }

        $record = ConvertTo-DiagSmartTelemetryRecord -PhysicalDisk $disk -ReliabilityCounter $null -DiskMetadata $metadata

        $record.Model | Should Be 'CT1000P3SSD8'
        $record.PowerOnHours | Should Be '—'
        $record.WearPct | Should Be '—'
        $record.Temperature | Should Be '—'
        $record.ReadErrors | Should Be '—'
    }

    It 'preserves an actual zero counter when the provider explicitly reports zero' {
        $disk = [pscustomobject]@{
            FriendlyName = 'Test SSD'
            Model = ''
            DeviceId = 1
            MediaType = 'SSD'
            Size = 500GB
            HealthStatus = 'Healthy'
        }
        $reliability = [pscustomobject]@{
            PowerOnHours = 0
            Wear = 0
            Temperature = 29
            ReadErrorsTotal = 0
        }

        $record = ConvertTo-DiagSmartTelemetryRecord -PhysicalDisk $disk -ReliabilityCounter $reliability

        $record.PowerOnHours | Should Be 0
        $record.WearPct | Should Be 0
        $record.Temperature | Should Be '29 °C'
        $record.ReadErrors | Should Be 0
    }

    It 'preserves SMART display characters when the module is loaded by Windows PowerShell 5.1' {
        $escapedModulePath = $modulePath.Replace("'", "''")
        $childCommand = @"
. '$escapedModulePath'
`$record = ConvertTo-DiagSmartTelemetryRecord -PhysicalDisk ([pscustomobject]@{
    FriendlyName = 'Synthetic'
    MediaType = 'SSD'
    Size = 100GB
    HealthStatus = 'Healthy'
    BusType = 'SATA'
    DeviceId = 0
}) -ReliabilityCounter ([pscustomobject]@{
    Temperature = 29
    Wear = `$null
    PowerOnHours = `$null
    ReadErrorsTotal = 0
}) -DiskMetadata `$null
`$record | ConvertTo-Json -Compress
"@
        $json = & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command $childCommand
        if ($LASTEXITCODE -ne 0) {
            throw 'Windows PowerShell 5.1 could not load the SMART telemetry module.'
        }
        $record = $json | ConvertFrom-Json

        $record.Temperature | Should Be '29 °C'
        $record.PowerOnHours | Should Be '—'
        $record.WearPct | Should Be '—'
        $record.ReadErrors | Should Be 0
    }
}
