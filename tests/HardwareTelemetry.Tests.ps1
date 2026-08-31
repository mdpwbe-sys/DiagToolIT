Describe 'DiagToolIT GPU telemetry' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\Diag-HardwareTelemetry.ps1')
    }

    It 'does not truncate a 24 GB GPU to the 32-bit WMI ceiling' {
        $registryBytes = [BitConverter]::GetBytes([UInt64](24GB))
        $vramGB = ConvertTo-DiagGpuMemoryGB -AdapterRamBytes ([UInt64]4293918720) -RegistryMemoryBytes $registryBytes

        if ($vramGB -ne 24) { throw "Expected 24 GB, got $vramGB GB." }
    }

    It 'accepts the NVIDIA qwMemorySize registry value used by high-VRAM cards' {
        $vramGB = ConvertTo-DiagGpuMemoryGB -AdapterRamBytes ([UInt64]4293918720) -RegistryMemoryBytes ([UInt64](24GB))

        if ($vramGB -ne 24) { throw "Expected 24 GB from qwMemorySize, got $vramGB GB." }
    }

    It 'keeps a normal adapter value when no registry override is available' {
        $vramGB = ConvertTo-DiagGpuMemoryGB -AdapterRamBytes ([UInt64](8GB))

        if ($vramGB -ne 8) { throw "Expected 8 GB, got $vramGB GB." }
    }
}
