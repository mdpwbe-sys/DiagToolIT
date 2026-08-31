function Invoke-DiagPrimePass {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$MaxNumber)

    $primeCount = 0
    for ($n = 2; $n -le $MaxNumber; $n++) {
        $isPrime = $true
        $limit = [math]::Sqrt($n)
        for ($d = 2; $d -le $limit; $d++) {
            if ($n % $d -eq 0) { $isPrime = $false; break }
        }
        if ($isPrime) { $primeCount++ }
    }
    return $primeCount
}

function Invoke-DiagCpuBenchmark {
    [CmdletBinding()]
    param(
        [ValidateRange(100, 100000)]
        [int]$MaxNumber = 12000,

        [ValidateRange(3, 9)]
        [int]$PassCount = 5
    )

    # Warm up the PowerShell arithmetic/JIT path so the first cold pass is not scored.
    $warmupWatch = [System.Diagnostics.Stopwatch]::StartNew()
    [void](Invoke-DiagPrimePass -MaxNumber $MaxNumber)
    $warmupWatch.Stop()

    $samples = [System.Collections.Generic.List[int]]::new()
    $primeCount = 0
    for ($pass = 0; $pass -lt $PassCount; $pass++) {
        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $primeCount = Invoke-DiagPrimePass -MaxNumber $MaxNumber
        $watch.Stop()
        $samples.Add([int]$watch.ElapsedMilliseconds)
    }

    $ordered = @($samples | Sort-Object)
    $middle = [math]::Floor($ordered.Count / 2)
    $median = if (($ordered.Count % 2) -eq 1) {
        [int]$ordered[$middle]
    } else {
        [int][math]::Round(($ordered[$middle - 1] + $ordered[$middle]) / 2)
    }

    [PSCustomObject]@{
        MaxNumber          = $MaxNumber
        PassCount          = $PassCount
        PrimeCount         = $primeCount
        WarmupMilliseconds = [int]$warmupWatch.ElapsedMilliseconds
        Samples            = @($samples)
        MedianMilliseconds = $median
    }
}

function ConvertTo-DiagCpuPerformanceScore {
    [CmdletBinding()]
    param([double]$Milliseconds)

    if ($Milliseconds -le 0) { return 100 }
    # 50 ms is the 100/100 reference point; slower runs degrade proportionally.
    return [math]::Min(100, [math]::Max(10, [math]::Round(5000 / [math]::Max(1, $Milliseconds))))
}
