[CmdletBinding()]
param(
    [Parameter(Mandatory, Position = 0)]
    [string]$Uri,

    [switch]$PassThru
)

$allowedUris = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
$allowedUris.Add('diagit://run?lang=FR', 'FR')
$allowedUris.Add('diagit://run?lang=NL', 'NL')
$allowedUris.Add('diagit://run?lang=EN', 'EN')
$allowedUris.Add('diagit://run?lang=DE', 'DE')
$allowedUris.Add('diagit://run/?lang=FR', 'FR')
$allowedUris.Add('diagit://run/?lang=NL', 'NL')
$allowedUris.Add('diagit://run/?lang=EN', 'EN')
$allowedUris.Add('diagit://run/?lang=DE', 'DE')

$normalizedUri = $Uri.Trim()
if ($normalizedUri.Length -ge 2 -and
    $normalizedUri.StartsWith('"', [StringComparison]::Ordinal) -and
    $normalizedUri.EndsWith('"', [StringComparison]::Ordinal)) {
    $normalizedUri = $normalizedUri.Substring(1, $normalizedUri.Length - 2).Trim()
}

if (-not $allowedUris.ContainsKey($normalizedUri)) {
    throw "Unsupported DiagToolIT protocol URL. Only an exact FR, NL, EN, or DE diagnostic URL is allowed. Received: [$Uri]"
}

$language = $allowedUris[$normalizedUri]
$launcherPath = Join-Path $PSScriptRoot 'Run-DiagElevated.bat'
if (-not (Test-Path -LiteralPath $launcherPath -PathType Leaf)) {
    throw "DiagToolIT launcher not found: $launcherPath"
}

$launchRequest = [PSCustomObject]@{
    Uri          = $normalizedUri
    Language     = $language
    LauncherPath = $launcherPath
}

if ($PassThru) {
    return $launchRequest
}

& $launcherPath $language
exit $LASTEXITCODE
