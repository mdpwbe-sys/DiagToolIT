Describe 'DiagToolIT CPU benchmark' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\Diag-Benchmark.ps1')
    }

    It 'warms up before collecting five timed passes and returns the median' {
        $result = Invoke-DiagCpuBenchmark -MaxNumber 250 -PassCount 5

        if ($result.Samples.Count -ne 5) { throw "Expected five samples, got $($result.Samples.Count)." }
        if ($result.WarmupMilliseconds -lt 0) { throw 'Warmup duration cannot be negative.' }
        $ordered = @($result.Samples | Sort-Object)
        $expectedMedian = $ordered[2]
        if ($result.MedianMilliseconds -ne $expectedMedian) {
            throw "Expected median $expectedMedian ms, got $($result.MedianMilliseconds) ms."
        }
    }

    It 'maps the measured latency to the same 0-100 CPU index shown in the report' {
        if ((ConvertTo-DiagCpuPerformanceScore -Milliseconds 50) -ne 100) { throw '50 ms should map to 100/100.' }
        if ((ConvertTo-DiagCpuPerformanceScore -Milliseconds 250) -ne 20) { throw '250 ms should map to 20/100.' }
    }
}
