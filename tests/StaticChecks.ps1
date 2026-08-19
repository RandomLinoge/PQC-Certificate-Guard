$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$scriptPath = Join-Path $root "src/PQC-Certificate-Guard.ps1"
$settingsPath = Join-Path $root "config/pqc-certificate-guard.settings.example.json"

$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) { throw ($errors | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" } | Out-String) }
Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json | Out-Null

$forbidden = @(
    '-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----',
    '[A-Za-z]:\\Users\\',
    '[A-Za-z]:\\Misc\\',
    '[A-Za-z]:\\sectools\\'
)
$hits = Select-String -Path $scriptPath,$settingsPath -Pattern $forbidden
if ($hits) { throw "Publication guardrail failed at: $($hits.Path):$($hits.LineNumber)" }

$requiredAlgorithms = @('ML-DSA-44','ML-DSA-65','ML-DSA-87','SLH-DSA-SHA2-256s','SLH-DSA-SHAKE-256f')
$text = Get-Content -LiteralPath $scriptPath -Raw
foreach ($algorithm in $requiredAlgorithms) {
    if (-not $text.Contains($algorithm)) { throw "Required algorithm missing: $algorithm" }
}

Write-Host "Static checks passed."
