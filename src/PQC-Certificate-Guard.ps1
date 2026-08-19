<#
PQC Certificate Guard

Purpose
  Builds a private laboratory X.509 hierarchy with standardized ML-DSA or
  SLH-DSA keys, signs files, and verifies both the detached signature and
  certificate chain through OpenSSL 3.5 or later.

Security boundary
  The generated hierarchy is a private trust domain. It is not browser or
  public WebPKI trust. Operator-specific values belong in
  pqc-certificate-guard.settings.json beside the script.
#>

$ErrorActionPreference = "Stop"
$script:ToolVersion = "v36.0"
$script:Esc = [char]27
$script:SettingsFile = Join-Path $PSScriptRoot "pqc-certificate-guard.settings.json"
$script:LastMessage = "Ready. Use arrows to move, ENTER to open. N toggles NMS."
$script:NmsEnabled = $true
$script:NmsTick = 0
$script:MenuIndex = 0
$script:ExitRequested = $false
$script:LastScreenKey = ""
$script:GreenDark = @(0, 44, 24)
$script:GreenMid = @(0, 160, 88)
$script:GreenBright = @(154, 255, 196)
$script:GreenPale = @(229, 255, 235)
$script:FrameWidth = 150
$script:FrameRows = 38
$script:AlgSupportCache = @{}
$script:PathCache = $null
$script:PathCacheAt = Get-Date "1900-01-01"
$script:StatusCache = $null
$script:StatusCacheAt = Get-Date "1900-01-01"

# =============================================================================
# OPERATOR SETTINGS AND SAFE DEFAULTS
# Relative paths are resolved from the script directory, which keeps a clean
# checkout portable and prevents workstation paths from entering source control.
# =============================================================================

$script:Settings = [ordered]@{
    Workspace  = "workspace"
    OpenSslPath = ""
    LabName    = "example-pqc-lab"
    OrgName    = "Example Research Lab"
    Country    = "XX"
    RootOU     = "PQC PKI Lab"
    SignerOU   = "PQC Signing"
    Algorithm  = "ML-DSA-87"
    Context    = "example-pqc-lab-ML-DSA-87-file-v1"
    LastSignedFile = ""
    LastSignatureFile = ""
    NmsEnabled = $true
}

$script:Algorithms = @(
    [pscustomobject]@{ Name="ML-DSA-87";          Family="ML-DSA"; Category="NIST Category 5 style"; Score=10; Profile="highest ML-DSA profile, practical high-strength signatures" },
    [pscustomobject]@{ Name="ML-DSA-65";          Family="ML-DSA"; Category="NIST Category 3 style"; Score=8;  Profile="balanced ML-DSA profile for signatures" },
    [pscustomobject]@{ Name="ML-DSA-44";          Family="ML-DSA"; Category="NIST Category 2 style"; Score=6;  Profile="smaller ML-DSA profile, lower strength tier" },
    [pscustomobject]@{ Name="SLH-DSA-SHA2-256f";  Family="SLH-DSA"; Category="NIST Category 5 style"; Score=10; Profile="hash-based fast-signing variant, large signatures" },
    [pscustomobject]@{ Name="SLH-DSA-SHA2-256s";  Family="SLH-DSA"; Category="NIST Category 5 style"; Score=10; Profile="hash-based small-signature variant, slower signing" },
    [pscustomobject]@{ Name="SLH-DSA-SHAKE-256f"; Family="SLH-DSA"; Category="NIST Category 5 style"; Score=10; Profile="SHAKE hash-based fast-signing variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHAKE-256s"; Family="SLH-DSA"; Category="NIST Category 5 style"; Score=10; Profile="SHAKE hash-based small-signature variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHA2-192f";  Family="SLH-DSA"; Category="NIST Category 3 style"; Score=8;  Profile="hash-based Category 3 fast variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHA2-192s";  Family="SLH-DSA"; Category="NIST Category 3 style"; Score=8;  Profile="hash-based Category 3 small variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHAKE-192f"; Family="SLH-DSA"; Category="NIST Category 3 style"; Score=8;  Profile="SHAKE Category 3 fast variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHAKE-192s"; Family="SLH-DSA"; Category="NIST Category 3 style"; Score=8;  Profile="SHAKE Category 3 small variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHA2-128f";  Family="SLH-DSA"; Category="NIST Category 1 style"; Score=5;  Profile="hash-based baseline fast variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHA2-128s";  Family="SLH-DSA"; Category="NIST Category 1 style"; Score=5;  Profile="hash-based baseline small variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHAKE-128f"; Family="SLH-DSA"; Category="NIST Category 1 style"; Score=5;  Profile="SHAKE baseline fast variant" },
    [pscustomobject]@{ Name="SLH-DSA-SHAKE-128s"; Family="SLH-DSA"; Category="NIST Category 1 style"; Score=5;  Profile="SHAKE baseline small variant" }
)

function Clear-GuardCaches {
    $script:PathCache = $null
    $script:PathCacheAt = Get-Date "1900-01-01"
    $script:StatusCache = $null
    $script:StatusCacheAt = Get-Date "1900-01-01"
}

function Save-Settings {
    $script:Settings.NmsEnabled = [bool]$script:NmsEnabled
    $json = $script:Settings | ConvertTo-Json -Depth 4
    Set-Content -Path $script:SettingsFile -Value $json -Encoding UTF8
    Clear-GuardCaches
}

function Load-Settings {
    if (Test-Path -LiteralPath $script:SettingsFile) {
        try {
            $loaded = Get-Content -LiteralPath $script:SettingsFile -Raw | ConvertFrom-Json
            foreach ($p in $loaded.PSObject.Properties) { $script:Settings[$p.Name] = $p.Value }
            if ($script:Settings.Contains("NmsEnabled")) { $script:NmsEnabled = [bool]$script:Settings.NmsEnabled }
        } catch { }
    }
}

Load-Settings

# =============================================================================
# COLOR / ANSI
# =============================================================================

function Ansi-Reset { return "$($script:Esc)[0m" }
function Ansi-Fg([int]$R,[int]$G,[int]$B) { return "$($script:Esc)[38;2;$R;$G;${B}m" }
function Ansi-Bg([int]$R,[int]$G,[int]$B) { return "$($script:Esc)[48;2;$R;$G;${B}m" }
function C([string]$Text,[int]$R,[int]$G,[int]$B) { return "$(Ansi-Fg $R $G $B)$Text$(Ansi-Reset)" }
function Cb([string]$Text,[int]$FR,[int]$FG,[int]$FB,[int]$BR,[int]$BG,[int]$BB) { return "$(Ansi-Fg $FR $FG $FB)$(Ansi-Bg $BR $BG $BB)$Text$(Ansi-Reset)" }
function DarkGreen([string]$Text) { return C $Text 0 90 50 }
function Emerald([string]$Text) { return C $Text 0 210 110 }
function Mint([string]$Text) { return C $Text 146 255 190 }
function BrightGreen([string]$Text) { return C $Text 210 255 220 }
function Pale([string]$Text) { return C $Text 230 255 235 }
function DimGreen([string]$Text) { return C $Text 110 150 126 }
function Amber([string]$Text) { return C $Text 255 215 120 }
function BadRed([string]$Text) { return C $Text 255 115 115 }
function Good([string]$Text) { return C $Text 95 255 150 }
function SoftBlue([string]$Text) { return C $Text 135 255 190 }

function GradientText {
    param(
        [AllowEmptyString()][string]$Text,
        [int[]]$Start = $script:GreenDark,
        [int[]]$End = $script:GreenBright
    )
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    $chars = $Text.ToCharArray()
    $count = [Math]::Max(1, $chars.Length - 1)
    $out = ""
    for ($i = 0; $i -lt $chars.Length; $i++) {
        $t = $i / $count
        $r = [int]($Start[0] + (($End[0] - $Start[0]) * $t))
        $g = [int]($Start[1] + (($End[1] - $Start[1]) * $t))
        $b = [int]($Start[2] + (($End[2] - $Start[2]) * $t))
        $out += "$(Ansi-Fg $r $g $b)$($chars[$i])"
    }
    return $out + (Ansi-Reset)
}

function VisibleLen([string]$Text) {
    if ($null -eq $Text) { return 0 }
    return (($Text -replace "$($script:Esc)\[[0-9;]*m", "")).Length
}

function PadAnsi([string]$Text,[int]$Width) {
    if ($null -eq $Text) { $Text = "" }
    $v = VisibleLen $Text
    if ($v -ge $Width) { return $Text }
    return $Text + (" " * ($Width - $v))
}

function StripAnsi([string]$Text) {
    if ($null -eq $Text) { return "" }
    return ([string]$Text) -replace "$($script:Esc)\[[0-9;]*m", ""
}

function FitAnsi([string]$Text,[int]$Width) {
    if ($null -eq $Text) { $Text = "" }
    if ($Width -le 0) { return "" }
    $v = VisibleLen $Text
    if ($v -le $Width) { return (PadAnsi $Text $Width) }

    # Safe fallback for oversized colored cells.
    # Losing color on an overlong cell is better than breaking the frame border.
    $plain = $Text -replace "$($script:Esc)\[[0-9;]*m", ""
    return (FitPlain $plain $Width)
}

function FitPlain([string]$Text,[int]$Width) {
    if ($null -eq $Text) { $Text = "" }
    if ($Width -le 0) { return "" }
    if ($Text.Length -le $Width) { return $Text + (" " * ($Width - $Text.Length)) }
    if ($Width -le 3) { return $Text.Substring(0, $Width) }
    return $Text.Substring(0, $Width - 3) + "..."
}

function ShortText([string]$Text,[int]$Width) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return "N/A" }
    $fixed = $Text
    if ($fixed.Length -le $Width) { return $fixed }
    if ($Width -le 3) { return $fixed.Substring(0,$Width) }
    return $fixed.Substring(0,$Width-3) + "..."
}

function WrapPlainText {
    param(
        [AllowEmptyString()][string]$Text,
        [int]$Width,
        [int]$MaxLines = 2
    )

    if ($Width -le 0) { return @('') }
    if ($null -eq $Text) { $Text = '' }
    $clean = [string]$Text
    $clean = $clean.Trim()
    if ($clean.Length -eq 0) { return @('') }

    $words = @($clean -split '\s+' | Where-Object { $_ -ne '' })
    $lines = New-Object System.Collections.Generic.List[string]
    $current = ''

    foreach ($wordRaw in $words) {
        $word = [string]$wordRaw
        while ($word.Length -gt $Width) {
            if (-not [string]::IsNullOrWhiteSpace($current)) {
                $lines.Add($current) | Out-Null
                $current = ''
                if ($MaxLines -gt 0 -and $lines.Count -ge $MaxLines) { return $lines.ToArray() }
            }
            $lines.Add($word.Substring(0, $Width)) | Out-Null
            $word = $word.Substring($Width)
            if ($MaxLines -gt 0 -and $lines.Count -ge $MaxLines) { return $lines.ToArray() }
        }

        if ([string]::IsNullOrWhiteSpace($current)) {
            $current = $word
        } elseif (($current.Length + 1 + $word.Length) -le $Width) {
            $current = "$current $word"
        } else {
            $lines.Add($current) | Out-Null
            if ($MaxLines -gt 0 -and $lines.Count -ge $MaxLines) { return $lines.ToArray() }
            $current = $word
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($current)) {
        $lines.Add($current) | Out-Null
    }

    if ($lines.Count -eq 0) { return @('') }
    return $lines.ToArray()
}

function KVWrapLines {
    param(
        [string]$Key,
        [string]$Value,
        [int]$ValueWidth = 58,
        [int]$KeyWidth = 12,
        [int]$MaxLines = 2
    )

    $parts = @(WrapPlainText -Text ([string]$Value) -Width $ValueWidth -MaxLines $MaxLines)
    $out = @()
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $kText = if ($i -eq 0) { "{0,-$KeyWidth}" -f $Key } else { " " * $KeyWidth }
        $out += "$(DimGreen $kText) $(Pale $($parts[$i]))"
    }
    return @($out)
}

function RedactPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return "N/A" }
    $fixed = $Path

    # Hide local folders in screenshot/result views, similar to the OpenPGP tool.
    # This version intentionally avoids regex so a Windows backslash cannot break parsing.
    $looksLikePath = $false
    try {
        if ($fixed.Length -ge 3 -and $fixed[1] -eq ':' -and ($fixed[2] -eq '\' -or $fixed[2] -eq '/')) {
            $looksLikePath = $true
        } elseif ($fixed.StartsWith('\\') -or $fixed.StartsWith('//')) {
            $looksLikePath = $true
        } elseif ($fixed.Contains('\') -or $fixed.Contains('/')) {
            $looksLikePath = $true
        }
    } catch {
        $looksLikePath = $false
    }

    if (-not $looksLikePath) { return $fixed }

    try {
        $trimmed = $fixed.TrimEnd([char[]]@('\','/'))
        $normalized = $trimmed.Replace('/', '\')
        $leaf = [System.IO.Path]::GetFileName($normalized)
        if ([string]::IsNullOrWhiteSpace($leaf)) { $leaf = "item" }
        return "[local path hidden]\$leaf"
    } catch {
        return "[local path hidden]"
    }
}

function CenterPlain([string]$Text,[int]$Width) {
    if ($null -eq $Text) { $Text = "" }
    if ($Text.Length -gt $Width) { return $Text.Substring(0,$Width) }
    $pad = $Width - $Text.Length
    $left = [Math]::Floor($pad/2)
    $right = $pad - $left
    return (" "*$left) + $Text + (" "*$right)
}

function Clear-PendingKeys {
    try { while ([Console]::KeyAvailable) { [void][Console]::ReadKey($true) } } catch { }
}

# =============================================================================
# OPENSSL / PATHS
# =============================================================================

function Get-OpenSslPath {
    $configured = [string]$script:Settings.OpenSslPath
    if (-not [string]::IsNullOrWhiteSpace($configured)) {
        if (-not [System.IO.Path]::IsPathRooted($configured)) {
            $configured = Join-Path $PSScriptRoot $configured
        }
        if (Test-Path -LiteralPath $configured -PathType Leaf) {
            return (Resolve-Path -LiteralPath $configured).Path
        }
    }
    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Keep machine-specific installation paths in the settings file. PATH is
    # used when OpenSslPath is empty.
    return "openssl"
}

function Join-OpenSslArguments {
    param([string[]]$ArgumentItems)

    $quoted = @()

    foreach ($item in @($ArgumentItems)) {
        if ($null -eq $item) {
            $quoted += '""'
            continue
        }

        $s = [string]$item

        if ($s -eq "") {
            $quoted += '""'
            continue
        }

        if ($s -match '[\s"]') {
            # Quote arguments for ProcessStartInfo.Arguments.
            # Keep Windows paths intact. Only escape embedded double quotes.
            $s = $s -replace '"', '\"'
            $quoted += '"' + $s + '"'
        } else {
            $quoted += $s
        }
    }

    return ($quoted -join ' ')
}

function Invoke-OpenSsl {
    param(
        [Alias("Args")]
        [string[]]$OpenSslArgs,
        [switch]$NoThrow
    )

    $exe = Get-OpenSslPath

    if ($null -eq $OpenSslArgs -or @($OpenSslArgs).Count -eq 0) {
        $msg = "OpenSSL wrapper was called without arguments. This is a script bug, not an OpenSSL failure."
        if ($NoThrow) { return [pscustomobject]@{ ExitCode=999; Output=$msg; Exe=$exe; Command=$exe } }
        throw $msg
    }

    $argText = Join-OpenSslArguments -ArgumentItems $OpenSslArgs
    $cmdText = "`"$exe`" $argText"

    # Use .NET Process instead of PowerShell native invocation.
    # This avoids NativeCommandError crashes when OpenSSL writes normal diagnostic text to stderr.
    # Use .Arguments instead of .ArgumentList for Windows PowerShell compatibility.
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $exe
    $psi.Arguments = $argText
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true

    $stdout = ""
    $stderr = ""
    $code = 999

    try {
        $p = [System.Diagnostics.Process]::new()
        $p.StartInfo = $psi
        [void]$p.Start()
        $stdout = $p.StandardOutput.ReadToEnd()
        $stderr = $p.StandardError.ReadToEnd()
        $p.WaitForExit()
        $code = $p.ExitCode
        $p.Dispose()
    } catch {
        $stderr = $_.Exception.Message
        $code = 998
    }

    $text = (($stdout, $stderr) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join "`n"
    $text = $text.Trim()

    if (-not $NoThrow -and $code -ne 0) {
        throw "OpenSSL failed:`n$cmdText`n$text"
    }

    return [pscustomobject]@{ ExitCode=$code; Output=$text; Exe=$exe; Command=$cmdText }
}

function Get-OpenSslVersion {
    try {
        $r = Invoke-OpenSsl -Args @("version") -NoThrow
        if (-not [string]::IsNullOrWhiteSpace($r.Output)) { return (($r.Output -split "`r?`n")[0]).Trim() }
    } catch { }
    return "UNKNOWN"
}

function Ensure-Workspace {
    $ws = Workspace
    foreach ($d in @($ws, (Join-Path $ws "certs"), (Join-Path $ws "private"), (Join-Path $ws "csr"), (Join-Path $ws "sig"), (Join-Path $ws "conf"), (Join-Path $ws "logs"))) {
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
    }
}

function AlgSlug([string]$Alg) { return ($Alg.ToLowerInvariant() -replace '[^a-z0-9]+','-').Trim('-') }
function LabName { return [string]$script:Settings.LabName }
function Workspace {
    $configured = [string]$script:Settings.Workspace
    if ([string]::IsNullOrWhiteSpace($configured)) { $configured = "workspace" }
    if ([System.IO.Path]::IsPathRooted($configured)) { return $configured }
    return (Join-Path $PSScriptRoot $configured)
}
function CertDir { return Join-Path (Workspace) "certs" }
function KeyDir { return Join-Path (Workspace) "private" }
function CsrDir { return Join-Path (Workspace) "csr" }
function SigDir { return Join-Path (Workspace) "sig" }
function ConfDir { return Join-Path (Workspace) "conf" }

function ExpectedPaths {
    $lab = LabName
    $slug = AlgSlug ([string]$script:Settings.Algorithm)
    return [pscustomobject]@{
        RootKey = Join-Path (KeyDir)  "$lab-$slug-root-ca.key.pem"
        RootCrt = Join-Path (CertDir) "$lab-$slug-root-ca.crt.pem"
        SignKey = Join-Path (KeyDir)  "$lab-$slug-file-signing.key.pem"
        SignCrt = Join-Path (CertDir) "$lab-$slug-file-signing.crt.pem"
        SignPub = Join-Path (CertDir) "$lab-$slug-file-signing.pub.pem"
        Csr     = Join-Path (CsrDir)  "$lab-$slug-file-signing.csr.pem"
    }
}

function Find-NewestFile {
    param([string[]]$Roots,[string[]]$Patterns)
    $hits = @()
    foreach ($root in @($Roots)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($pat in @($Patterns)) {
            try { $hits += @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter $pat -ErrorAction SilentlyContinue) } catch { }
        }
    }
    $hits = @($hits | Sort-Object LastWriteTime -Descending | Select-Object -Unique)
    if (@($hits).Count -eq 0) { return $null }
    return $hits[0].FullName
}

function Test-CertReadableFast {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $r = Invoke-OpenSsl -Args @("x509","-in",$Path,"-noout","-subject") -NoThrow
        return ($r.ExitCode -eq 0 -and $r.Output -match "subject=")
    } catch { return $false }
}

function Test-KeyReadableFast {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $false }
    try {
        $r = Invoke-OpenSsl -Args @("pkey","-in",$Path,"-noout","-text") -NoThrow
        return ($r.ExitCode -eq 0)
    } catch { return $false }
}

function Find-NewestReadableCert {
    param([string[]]$Roots,[string[]]$Patterns)
    $hits = @()
    foreach ($root in @($Roots)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($pat in @($Patterns)) {
            try { $hits += @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter $pat -ErrorAction SilentlyContinue) } catch { }
        }
    }
    $hits = @($hits | Sort-Object LastWriteTime -Descending | Select-Object -Unique)
    foreach ($h in $hits) {
        if (Test-CertReadableFast $h.FullName) { return $h.FullName }
    }
    if (@($hits).Count -gt 0) { return $hits[0].FullName }
    return $null
}

function Find-NewestReadableKey {
    param([string[]]$Roots,[string[]]$Patterns)
    $hits = @()
    foreach ($root in @($Roots)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($pat in @($Patterns)) {
            try { $hits += @(Get-ChildItem -LiteralPath $root -Recurse -File -Filter $pat -ErrorAction SilentlyContinue) } catch { }
        }
    }
    $hits = @($hits | Sort-Object LastWriteTime -Descending | Select-Object -Unique)
    foreach ($h in $hits) {
        if (Test-KeyReadableFast $h.FullName) { return $h.FullName }
    }
    if (@($hits).Count -gt 0) { return $hits[0].FullName }
    return $null
}

function Pick-CertPath {
    param([string]$Expected,[string[]]$Roots,[string[]]$Patterns)
    if (Test-CertReadableFast $Expected) { return $Expected }
    $found = Find-NewestReadableCert -Roots $Roots -Patterns $Patterns
    if ($found) { return $found }
    if (Test-Path -LiteralPath $Expected) { return $Expected }
    return $null
}

function Pick-KeyPath {
    param([string]$Expected,[string[]]$Roots,[string[]]$Patterns)
    if (Test-KeyReadableFast $Expected) { return $Expected }
    $found = Find-NewestReadableKey -Roots $Roots -Patterns $Patterns
    if ($found) { return $found }
    if (Test-Path -LiteralPath $Expected) { return $Expected }
    return $null
}

function Pick-FirstReadableCert {
    param([string[]]$Candidates)
    foreach ($c in @($Candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        if (Test-CertReadableFast $c) { return $c }
    }
    foreach ($c in @($Candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

function Pick-FirstReadableKey {
    param([string[]]$Candidates)
    foreach ($c in @($Candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        if (Test-KeyReadableFast $c) { return $c }
    }
    foreach ($c in @($Candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    return $null
}

function Get-ExplicitPathCandidates {
    $p = ExpectedPaths
    $ws = Workspace
    $certRoots = @((Join-Path $ws "certs"))
    $keyRoots = @((Join-Path $ws "private"))
    $lab = LabName
    $alg = [string]$script:Settings.Algorithm
    $algSlug = AlgSlug $alg
    $algCompact = ($alg -replace '-','').ToLowerInvariant()

    $rootCerts = New-Object System.Collections.Generic.List[string]
    $signCerts = New-Object System.Collections.Generic.List[string]
    $rootKeys  = New-Object System.Collections.Generic.List[string]
    $signKeys  = New-Object System.Collections.Generic.List[string]
    $signPubs  = New-Object System.Collections.Generic.List[string]

    $rootCerts.Add($p.RootCrt) | Out-Null
    $signCerts.Add($p.SignCrt) | Out-Null
    $rootKeys.Add($p.RootKey) | Out-Null
    $signKeys.Add($p.SignKey) | Out-Null
    $signPubs.Add($p.SignPub) | Out-Null

    foreach ($cr in $certRoots) {
        $rootCerts.Add((Join-Path $cr "$lab-$algCompact-root-ca.crt.pem")) | Out-Null
        $rootCerts.Add((Join-Path $cr "$lab-$algSlug-root-ca.crt.pem")) | Out-Null
        $rootCerts.Add((Join-Path $cr "$lab-mldsa87-root-ca.crt.pem")) | Out-Null
        $rootCerts.Add((Join-Path $cr "$lab-mldsa65-root-ca.crt.pem")) | Out-Null
        $rootCerts.Add((Join-Path $cr "$lab-mldsa44-root-ca.crt.pem")) | Out-Null
        $rootCerts.Add((Join-Path $cr "$lab-root-ca.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-$algCompact-file-signing.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-$algSlug-file-signing.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-file-signing-$algCompact.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-file-signing-mldsa87.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-file-signing-mldsa65.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-file-signing-mldsa44.crt.pem")) | Out-Null
        $signCerts.Add((Join-Path $cr "$lab-file-signer.crt.pem")) | Out-Null
        $signPubs.Add((Join-Path $cr "$lab-$algCompact-file-signing.pub.pem")) | Out-Null
        $signPubs.Add((Join-Path $cr "$lab-$algSlug-file-signing.pub.pem")) | Out-Null
        $signPubs.Add((Join-Path $cr "$lab-file-signing-$algCompact.pub.pem")) | Out-Null
        $signPubs.Add((Join-Path $cr "$lab-file-signing-mldsa87-from-cert.pub.pem")) | Out-Null
        $signPubs.Add((Join-Path $cr "$lab-file-signing-mldsa87.pub.pem")) | Out-Null
    }

    foreach ($kr in $keyRoots) {
        $rootKeys.Add((Join-Path $kr "$lab-$algCompact-root-ca.key.pem")) | Out-Null
        $rootKeys.Add((Join-Path $kr "$lab-$algSlug-root-ca.key.pem")) | Out-Null
        $rootKeys.Add((Join-Path $kr "$lab-mldsa87-root-ca.key.pem")) | Out-Null
        $rootKeys.Add((Join-Path $kr "$lab-mldsa65-root-ca.key.pem")) | Out-Null
        $rootKeys.Add((Join-Path $kr "$lab-mldsa44-root-ca.key.pem")) | Out-Null
        $rootKeys.Add((Join-Path $kr "$lab-root-ca.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-$algCompact-file-signing.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-$algSlug-file-signing.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-file-signing-$algCompact.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-file-signing-mldsa87.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-file-signing-mldsa65.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-file-signing-mldsa44.key.pem")) | Out-Null
        $signKeys.Add((Join-Path $kr "$lab-file-signer.key.pem")) | Out-Null
    }

    return [pscustomobject]@{ RootCerts=$rootCerts; SignCerts=$signCerts; RootKeys=$rootKeys; SignKeys=$signKeys; SignPubs=$signPubs }
}


function Resolve-LabPaths {
    Ensure-Workspace

    # Status rendering calls this frequently. Cache path resolution briefly so the
    # menu remains fluid and does not deep-scan the disk on every NMS repaint.
    if ($script:PathCache -and ((Get-Date) - $script:PathCacheAt).TotalSeconds -lt 8) {
        return $script:PathCache
    }

    $p = ExpectedPaths
    $c = Get-ExplicitPathCandidates

    # First try exact expected and known historical filenames. This is fast and avoids
    # the 10-15 second blank screen caused by recursive scans from the live dashboard.
    $rootCrt = Pick-FirstReadableCert @($c.RootCerts)
    $signCrt = Pick-FirstReadableCert @($c.SignCerts)
    $rootKey = Pick-FirstReadableKey @($c.RootKeys)
    $signKey = Pick-FirstReadableKey @($c.SignKeys)
    $signPub = Pick-FirstReadableCert @($c.SignPubs)
    if (-not $signPub) {
        foreach ($pub in @($c.SignPubs | Select-Object -Unique)) { if (Test-Path -LiteralPath $pub) { $signPub = $pub; break } }
    }

    # Only if fast candidates miss, scan the configured lab root. Keeping the
    # search bounded prevents menu refreshes from traversing unrelated folders.
    if (-not $rootCrt -or -not $signCrt -or -not $rootKey -or -not $signKey) {
        $scanRoots = @((Workspace))
        $rootPatterns = @("*mldsa*root*ca*.crt.pem", "*ml-dsa*root*ca*.crt.pem", "*root*ca*.crt.pem")
        $signPatterns = @("*mldsa*file*sign*.crt.pem", "*ml-dsa*file*sign*.crt.pem", "*file*sign*.crt.pem", "*file-signer*.crt.pem", "*signer*.crt.pem")
        $rootKeyPatterns = @("*mldsa*root*ca*.key.pem", "*ml-dsa*root*ca*.key.pem", "*root*ca*.key.pem")
        $signKeyPatterns = @("*mldsa*file*sign*.key.pem", "*ml-dsa*file*sign*.key.pem", "*file*sign*.key.pem", "*file-signer*.key.pem", "*signer*.key.pem")

        if (-not $rootCrt) { $rootCrt = Pick-CertPath -Expected $p.RootCrt -Roots $scanRoots -Patterns $rootPatterns }
        if (-not $signCrt) { $signCrt = Pick-CertPath -Expected $p.SignCrt -Roots $scanRoots -Patterns $signPatterns }
        if (-not $rootKey) { $rootKey = Pick-KeyPath -Expected $p.RootKey -Roots $scanRoots -Patterns $rootKeyPatterns }
        if (-not $signKey) { $signKey = Pick-KeyPath -Expected $p.SignKey -Roots $scanRoots -Patterns $signKeyPatterns }
        if (-not $signPub -and (Test-Path -LiteralPath $p.SignPub)) { $signPub = $p.SignPub }
    }

    $result = [pscustomobject]@{
        RootCrt = $rootCrt
        SignCrt = $signCrt
        RootKey = $rootKey
        SignKey = $signKey
        SignPub = $signPub
        Expected = $p
    }
    $script:PathCache = $result
    $script:PathCacheAt = Get-Date
    return $result
}

# =============================================================================
# CERTIFICATE INFO / STRENGTH
# =============================================================================

function Get-CnFromDn([string]$Dn) {
    $fixed = $Dn
    if ($fixed -match 'CN\s*=\s*([^,]+)') { return $matches[1].Trim() }
    return (ShortText $fixed 80)
}

function ShortHex([string]$Value,[int]$Left=16,[int]$Right=16) {
    $clean = ($Value -replace '[^a-fA-F0-9]','').ToUpperInvariant()
    if ([string]::IsNullOrWhiteSpace($clean)) { return "N/A" }
    if ($clean.Length -le ($Left+$Right)) { return $clean }
    return $clean.Substring(0,$Left) + "..." + $clean.Substring($clean.Length-$Right)
}

function Get-CertInfo {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Exists=$false; ParseOk=$false; Path=$Path; SubjectCN="MISSING"; IssuerCN="MISSING"; Serial="N/A"; NotBefore="N/A"; NotAfter="N/A"; PubAlg="N/A"; SigAlg="N/A"; FP="N/A"; Error="file not found" }
    }
    try {
        $meta = Invoke-OpenSsl -Args @("x509","-in",$Path,"-noout","-subject","-issuer","-serial","-dates","-fingerprint","-sha256") -NoThrow
        $text = Invoke-OpenSsl -Args @("x509","-in",$Path,"-noout","-text") -NoThrow
        if ($meta.ExitCode -ne 0) { throw $meta.Output }
        $lines = @($meta.Output -split "`r?`n")
        $subject = (($lines | Where-Object { $_ -match '^subject=' } | Select-Object -First 1) -replace '^subject=\s*','')
        $issuer = (($lines | Where-Object { $_ -match '^issuer=' } | Select-Object -First 1) -replace '^issuer=\s*','')
        $serial = (($lines | Where-Object { $_ -match '^serial=' } | Select-Object -First 1) -replace '^serial=','')
        $nb = (($lines | Where-Object { $_ -match '^notBefore=' } | Select-Object -First 1) -replace '^notBefore=','')
        $na = (($lines | Where-Object { $_ -match '^notAfter=' } | Select-Object -First 1) -replace '^notAfter=','')
        $fpLine = ($lines | Where-Object { $_ -match 'Fingerprint=' } | Select-Object -First 1)
        $fp = ($fpLine -replace '^.*Fingerprint=','')
        $tlines = @($text.Output -split "`r?`n")
        $pub = (($tlines | Where-Object { $_ -match 'Public Key Algorithm:' } | Select-Object -First 1) -replace '^\s*Public Key Algorithm:\s*','')
        $sig = (($tlines | Where-Object { $_ -match 'Signature Algorithm:' } | Select-Object -First 1) -replace '^\s*Signature Algorithm:\s*','')
        if ([string]::IsNullOrWhiteSpace($pub)) { $pub = "N/A" }
        if ([string]::IsNullOrWhiteSpace($sig)) { $sig = "N/A" }
        return [pscustomobject]@{ Exists=$true; ParseOk=$true; Path=$Path; SubjectCN=(Get-CnFromDn $subject); IssuerCN=(Get-CnFromDn $issuer); Serial=$serial; NotBefore=$nb; NotAfter=$na; PubAlg=$pub; SigAlg=$sig; FP=(ShortHex $fp); Error="" }
    } catch {
        return [pscustomobject]@{ Exists=$true; ParseOk=$false; Path=$Path; SubjectCN="UNREADABLE"; IssuerCN="UNREADABLE"; Serial="N/A"; NotBefore="N/A"; NotAfter="N/A"; PubAlg="N/A"; SigAlg="N/A"; FP="N/A"; Error=$_.Exception.Message }
    }
}

function Get-AlgorithmProfile([string]$Alg) {
    $a = @($script:Algorithms | Where-Object { $_.Name -eq $Alg } | Select-Object -First 1)
    if (@($a).Count -gt 0) { return $a[0] }
    return [pscustomobject]@{ Name=$Alg; Family="UNKNOWN"; Category="unknown strength profile"; Score=0; Profile="unknown" }
}

function StrengthBar([int]$Score,[int]$Cells=10) {
    $s = [Math]::Max(0,[Math]::Min(10,$Score))
    $filled = [Math]::Round(($s / 10) * $Cells)
    $bar = ""
    for ($i=0; $i -lt $Cells; $i++) {
        if ($i -lt $filled) { $bar += "█" } else { $bar += "░" }
    }
    return $bar
}

function StrengthBarColored([int]$Score,[int]$Cells=10) {
    $s = [Math]::Max(0,[Math]::Min(10,$Score))
    $filled = [Math]::Round(($s / 10) * $Cells)
    $out = ""
    for ($i=0; $i -lt $Cells; $i++) {
        if ($i -lt $filled) {
            $t = if ($Cells -le 1) { 1 } else { $i / ([Math]::Max(1,$Cells-1)) }
            $r = [int]($script:GreenDark[0] + (($script:GreenBright[0] - $script:GreenDark[0]) * $t))
            $g = [int]($script:GreenDark[1] + (($script:GreenBright[1] - $script:GreenDark[1]) * $t))
            $b = [int]($script:GreenDark[2] + (($script:GreenBright[2] - $script:GreenDark[2]) * $t))
            $out += "$(Ansi-Fg $r $g $b)█"
        } else {
            $out += "$(Ansi-Fg 24 64 42)░"
        }
    }
    return $out + (Ansi-Reset)
}

function Get-StrengthText([string]$Alg) {
    $p = Get-AlgorithmProfile $Alg
    return "$(StrengthBarColored $p.Score)  $(DimGreen $p.Category)"
}

function Test-AlgSupportFromList([string]$Alg) {
    try {
        $l1 = (Invoke-OpenSsl -Args @("list","-public-key-algorithms") -NoThrow).Output
        $l2 = (Invoke-OpenSsl -Args @("list","-signature-algorithms") -NoThrow).Output
        $all = "$l1`n$l2"
        if ($all -match [regex]::Escape($Alg)) { return $true }
        $compact = $Alg -replace '-',''
        if (($all -replace '[^A-Za-z0-9]','') -match [regex]::Escape($compact)) { return $true }
    } catch { }
    return $false
}

function Test-AlgSupportByKeyGen([string]$Alg) {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("pqc-test-{0}-{1}.pem" -f (AlgSlug $Alg), [guid]::NewGuid().ToString("N"))
    try {
        $r = Invoke-OpenSsl -Args @("genpkey","-algorithm",$Alg,"-out",$tmp) -NoThrow
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        return ($r.ExitCode -eq 0)
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        return $false
    }
}

function Test-AlgorithmSupport([string]$Alg,[switch]$FastOnly) {
    if ($script:AlgSupportCache.ContainsKey($Alg)) { return [bool]$script:AlgSupportCache[$Alg] }
    if (Test-AlgSupportFromList $Alg) { $script:AlgSupportCache[$Alg] = $true; return $true }
    if ($FastOnly) { return $false }
    $ok = Test-AlgSupportByKeyGen $Alg
    $script:AlgSupportCache[$Alg] = [bool]$ok
    return [bool]$ok
}

function Get-ChainStatus {
    $paths = Resolve-LabPaths
    if (-not $paths.RootCrt -or -not $paths.SignCrt) { return "MISSING" }
    $r = Invoke-OpenSsl -Args @("verify","-CAfile",$paths.RootCrt,$paths.SignCrt) -NoThrow
    if ($r.ExitCode -eq 0) { return "VALID" }
    return "FAILED"
}

function Convert-OpenSslDateSafe {
    param([string]$DateText)
    if ([string]::IsNullOrWhiteSpace($DateText) -or $DateText -eq "N/A") { return $null }
    try {
        $culture = [System.Globalization.CultureInfo]::InvariantCulture
        $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
        $formats = @("MMM d HH:mm:ss yyyy 'GMT'", "MMM dd HH:mm:ss yyyy 'GMT'")
        $dt = [datetime]::MinValue
        foreach ($fmt in $formats) {
            if ([datetime]::TryParseExact($DateText, $fmt, $culture, $styles, [ref]$dt)) { return $dt }
        }
        return [datetime]::Parse($DateText, $culture, $styles)
    } catch { return $null }
}

function Get-ChainDiagnosis {
    try {
        $paths = Resolve-LabPaths
        if (-not $paths.RootCrt -or -not $paths.SignCrt) { return "Root CA or file-signing certificate is missing." }
        $verify = Invoke-OpenSsl -Args @("verify","-CAfile",$paths.RootCrt,$paths.SignCrt) -NoThrow
        if ($verify.ExitCode -eq 0) { return "Root CA verifies the file-signing certificate." }

        $root = Get-CertInfo $paths.RootCrt
        $sign = Get-CertInfo $paths.SignCrt
        $rootName = [string]$root.SubjectCN
        $issuerName = [string]$sign.IssuerCN
        $rootDate = Convert-OpenSslDateSafe ([string]$root.NotBefore)
        $signDate = Convert-OpenSslDateSafe ([string]$sign.NotBefore)

        if ($rootDate -ne $null -and $signDate -ne $null -and $rootDate -gt $signDate) {
            return "The current root CA is newer than the file-signing certificate. Regenerate the file-signing certificate from this root, then sign the file again."
        }
        if ($rootName -eq $issuerName) {
            return "Issuer name matches, but the root public key does not verify the signer certificate. This usually means the signer was issued by an older root with the same CN."
        }
        return "Signer issuer CN does not match the current root CN. Import the matching root or issue a new file-signing certificate."
    } catch {
        return "Chain diagnosis unavailable: $($_.Exception.Message)"
    }
}

function Update-FrameSize {
    try {
        $ww = [Console]::WindowWidth
        $hh = [Console]::WindowHeight

        # Keep the frame centered instead of glued to the left edge.
        # Reserve a small side margin when the terminal is wide enough.
        $targetWidth = [Math]::Min(($ww - 4), 158)
        if ($targetWidth -lt 116) { $targetWidth = [Math]::Max(100, $ww - 1) }

        $script:FrameWidth = $targetWidth
        $script:FrameRows = [Math]::Max(18, $hh - 1)
    } catch {
        $script:FrameWidth = 150
        $script:FrameRows = 38
    }
}

function Get-FrameLeftPad {
    try {
        $ww = [Console]::WindowWidth
        $pad = [Math]::Floor(($ww - $script:FrameWidth) / 2)
        if ($pad -lt 0) { $pad = 0 }
        return (" " * $pad)
    } catch {
        return ""
    }
}

function Write-FrameLines {
    param([string[]]$Lines)
    $pad = Get-FrameLeftPad
    foreach ($l in @($Lines)) { Write-Host ($pad + $l) }
}

# =============================================================================
# FRAME RENDERING
# =============================================================================

function FrameTop([string]$Label="") {
    $inner = $script:FrameWidth - 2
    if ([string]::IsNullOrWhiteSpace($Label)) { return GradientText ("╔" + ("═"*$inner) + "╗") }
    $lab = " $Label "
    $rem = $inner - $lab.Length
    if ($rem -lt 4) { return GradientText ("╔" + (FitPlain $lab $inner) + "╗") }
    $left = [Math]::Floor($rem/2); $right = $rem - $left
    return GradientText ("╔" + ("═"*$left) + $lab + ("═"*$right) + "╗")
}

function FrameBottom([string]$Label="") {
    $inner = $script:FrameWidth - 2
    if ([string]::IsNullOrWhiteSpace($Label)) { return GradientText ("╚" + ("═"*$inner) + "╝") }
    $lab = " $Label "
    $rem = $inner - $lab.Length
    if ($rem -lt 4) { return GradientText ("╚" + (FitPlain $lab $inner) + "╝") }
    $left = [Math]::Floor($rem/2); $right = $rem - $left
    return GradientText ("╚" + ("═"*$left) + $lab + ("═"*$right) + "╝")
}

function FrameLine([string]$Text="") {
    $inner = $script:FrameWidth - 2
    $leftPad = "   "; $rightPad = "   "
    $contentWidth = $inner - $leftPad.Length - $rightPad.Length
    return "$(DarkGreen "║")$leftPad$(FitAnsi $Text $contentWidth)$rightPad$(DarkGreen "║")"
}

function FrameCenter([string]$Text) {
    $inner = $script:FrameWidth - 2
    return "$(DarkGreen "║")$(GradientText (CenterPlain $Text $inner) $script:GreenDark $script:GreenPale)$(DarkGreen "║")"
}

function KVLine([string]$Key,[string]$Value,[int]$KeyWidth=12) {
    $k = "{0,-$KeyWidth}" -f $Key
    return "$(DimGreen $k) $(Pale $Value)"
}

function StatusColored([string]$Status) {
    if ($Status -eq "VALID" -or $Status -eq "SUPPORTED" -or $Status -eq "OK") { return Good $Status }
    if ($Status -eq "NOT CHECKED" -or $Status -eq "MISSING" -or $Status -match "NOT FOUND") { return Amber $Status }
    return BadRed $Status
}

function DualFrameLine([string]$A,[string]$B) {
    $inner = $script:FrameWidth - 2
    $leftPad = "  "; $rightPad = "  "; $gap = "   "
    $cw = $inner - $leftPad.Length - $rightPad.Length
    $c1 = [Math]::Floor(($cw - $gap.Length) / 2)
    $c2 = $cw - $c1 - $gap.Length
    return "$(DarkGreen "║")$leftPad$(FitAnsi $A $c1)$gap$(FitAnsi $B $c2)$rightPad$(DarkGreen "║")"
}

function TripleFrameLine([string]$A,[string]$B,[string]$C) {
    $inner = $script:FrameWidth - 2
    $leftPad = "   "; $rightPad = "   "; $gap = "    "
    $cw = $inner - $leftPad.Length - $rightPad.Length
    $c1 = [Math]::Floor(($cw - (2*$gap.Length)) / 3)
    $c2 = $c1
    $c3 = $cw - $c1 - $c2 - (2*$gap.Length)
    return "$(DarkGreen "║")$leftPad$(FitAnsi $A $c1)$gap$(FitAnsi $B $c2)$gap$(FitAnsi $C $c3)$rightPad$(DarkGreen "║")"
}

# =============================================================================
# NMS MENU
# =============================================================================

$script:NmsChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#$%&*+=?@/"

function New-NmsText {
    param(
        [string]$Text,
        [int]$Index,
        [bool]$Selected=$false,
        [switch]$Subtle
    )

    # Real No More Secrets style layer:
    # same line length, mostly readable, with a moving encrypted band.
    if (-not $script:NmsEnabled) { return $Text }
    if ($null -eq $Text) { return "" }

    $source = [string]$Text
    if ($source.Length -le 0) { return $source }

    $glyphs = $script:NmsChars.ToCharArray()
    $frame = 0
    try { $frame = [int]$script:NmsTick } catch { $frame = 0 }

    $baseReveal = 0.82
    if ($Subtle) { $baseReveal = 0.89 }
    if ($Selected) { $baseReveal = 0.94 }

    $period = [Math]::Max(14, $source.Length + 10)
    $center = (($frame + ($Index * 5)) % $period) - 5
    $sb = New-Object System.Text.StringBuilder

    for ($i = 0; $i -lt $source.Length; $i++) {
        $ch = $source[$i]
        $chText = [string]$ch
        $eligible = ([char]::IsLetterOrDigit($ch) -or $chText -eq '_' -or $chText -eq '-' -or $chText -eq '/' -or $chText -eq '.')
        if (-not $eligible) {
            [void]$sb.Append($ch)
            continue
        }

        $distance = [Math]::Abs($i - $center)
        $bandPenalty = 0.0
        if ($distance -le 1) { $bandPenalty = 0.34 }
        elseif ($distance -le 3) { $bandPenalty = 0.20 }
        elseif ($distance -le 5) { $bandPenalty = 0.08 }

        $sine = ([Math]::Sin((($i * 0.55) + ($frame * 0.32) + ($Index * 0.07))) + 1.0) / 2.0
        $effectiveReveal = $baseReveal - ($bandPenalty * (0.65 + (0.35 * $sine)))
        if ($effectiveReveal -lt 0.55) { $effectiveReveal = 0.55 }
        if ($effectiveReveal -gt 0.98) { $effectiveReveal = 0.98 }

        $code = [int][char]$ch
        $gate = ((($i * 31) + ($frame * 11) + ($Index * 13) + $code) % 100) / 100.0
        if ($gate -lt $effectiveReveal) {
            [void]$sb.Append($ch)
        } else {
            $glyphIndex = (($i * 9) + ($frame * 5) + ($Index * 3) + $code) % $glyphs.Length
            [void]$sb.Append($glyphs[$glyphIndex])
        }
    }

    return $sb.ToString()
}

function Get-NmsFooterText {
    param([int]$MaxWidth)

    if ($MaxWidth -lt 20) { $MaxWidth = 20 }

    if (-not $script:NmsEnabled) {
        return (ShortText "NO MORE SECRETS :: standby, press N to activate reveal layer" $MaxWidth)
    }

    # Real NMS: the identity stays readable, the payload gets a moving encrypted/revealed wave.
    $payload = "POST-QUANTUM CERTIFICATE GUARD :: ML-DSA SLH-DSA X.509 SIGNATURE CHAIN"
    $wave = New-NmsText -Text $payload -Index 120 -Selected $true
    return (ShortText ("NO MORE SECRETS :: " + $wave) $MaxWidth)
}

function Get-QuantumSignalText {
    param([int]$MaxWidth)

    if ($MaxWidth -lt 20) { $MaxWidth = 20 }

    # Separate PQC signal line. This is intentionally not NMS.
    # It gives the console a live trust-grid pulse while NMS remains the No More Secrets layer.
    $tokens = @("HASH-LOCK", "TRUST-GRID", "EVIDENCE", "ML-DSA", "SLH-DSA", "X.509", "CHAIN", "DETACHED-SIG")
    $barWidth = [Math]::Min(26, [Math]::Max(10, $MaxWidth - 72))
    $tick = 0
    try { $tick = [int]$script:NmsTick } catch { $tick = 0 }
    $pos = $tick % $barWidth
    $barChars = New-Object System.Collections.Generic.List[string]

    for ($i = 0; $i -lt $barWidth; $i++) {
        $d = [Math]::Abs($i - $pos)
        if ($d -eq 0) {
            $barChars.Add("◆") | Out-Null
        } elseif ($d -le 2) {
            $barChars.Add("▓") | Out-Null
        } else {
            $barChars.Add("░") | Out-Null
        }
    }

    $phase = [Math]::Floor($tick / 4) % $tokens.Count
    $t1 = $tokens[$phase]
    $t2 = $tokens[($phase + 1) % $tokens.Count]
    $t3 = $tokens[($phase + 2) % $tokens.Count]

    return (ShortText ("quantum signal " + (-join $barChars) + " :: $t1 -> $t2 -> $t3") $MaxWidth)
}
function New-MenuItem([string]$Label,[string]$Value,[string]$Hint,[string]$Shortcut="") {
    return [pscustomobject]@{ Label=$Label; Value=$Value; Hint=$Hint; Shortcut=$Shortcut }
}

function Get-PostQuantumBanner {
    $raw = @'
 _____         _       _____             _
|  _  |___ ___| |_ ___|     |_ _ ___ ___| |_ _ _ _____
|   __| . |_ -|  _|___|  |  | | | .'|   |  _| | |     |
|__|  |___|___|_|     |__  _|___|__,|_|_|_| |___|_|_|_|
 _____         _   _ ___ |__|      _           _____               _
|     |___ ___| |_|_|  _|_|___ ___| |_ ___ ___|   __|_ _ ___ ___ _| |
|   --| -_|  _|  _| |  _| |  _| .'|  _| -_|___|  |  | | | .'|  _| . |
|_____|___|_| |_| |_|_| |_|___|__,|_| |___|   |_____|___|__,|_| |___|
'@
    return @($raw -split "`r?`n" | Where-Object { $_ -ne "" })
}

function FrameBannerLine([string]$Text) {
    $inner = $script:FrameWidth - 2
    $leftPad = "   "; $rightPad = "   "
    $contentWidth = $inner - $leftPad.Length - $rightPad.Length
    $plain = if ($Text.Length -gt $contentWidth) { $Text.Substring(0, $contentWidth) } else { CenterPlain $Text $contentWidth }
    return "$(DarkGreen "║")$leftPad$(GradientText $plain $script:GreenDark $script:GreenPale)$rightPad$(DarkGreen "║")"
}

function Get-SafeValue {
    param(
        [scriptblock]$Block,
        $Fallback = "N/A"
    )
    try {
        $v = & $Block
        if ($null -eq $v) { return $Fallback }
        if ($v -is [string] -and [string]::IsNullOrWhiteSpace($v)) { return $Fallback }
        return $v
    } catch {
        return $Fallback
    }
}

function Get-StatusLines {
    if ($script:StatusCache -and ((Get-Date) - $script:StatusCacheAt).TotalSeconds -lt 2) {
        return @($script:StatusCache)
    }

    $out = @()
    try { $paths = Resolve-LabPaths } catch { $paths = $null }
    $root = Get-SafeValue { Get-CertInfo $paths.RootCrt } $null
    $sign = Get-SafeValue { Get-CertInfo $paths.SignCrt } $null
    if ($null -eq $root -or ($root -is [string])) { $root = [pscustomobject]@{ SubjectCN="MISSING"; NotBefore="N/A"; NotAfter="N/A"; PubAlg="N/A"; SigAlg="N/A"; FP="N/A" } }
    if ($null -eq $sign -or ($sign -is [string])) { $sign = [pscustomobject]@{ SubjectCN="MISSING"; NotBefore="N/A"; NotAfter="N/A"; PubAlg="N/A"; SigAlg="N/A"; FP="N/A" } }

    $profile = Get-AlgorithmProfile ([string]$script:Settings.Algorithm)
    $support = Get-SafeValue { if (Test-AlgorithmSupport ([string]$script:Settings.Algorithm) -FastOnly) { "SUPPORTED" } else { "CHECK NEEDED" } } "CHECK NEEDED"
    $chain = Get-SafeValue { Get-ChainStatus } "CHECK NEEDED"

    $out += @(KVWrapLines "OpenSSL" (RedactPath (Get-SafeValue { Get-OpenSslPath } "openssl")) 58 12 2)
    $out += @(KVWrapLines "Version" (Get-SafeValue { Get-OpenSslVersion } "UNKNOWN") 58 12 2)
    $out += @(KVWrapLines "Workspace" (RedactPath ([string]$script:Settings.Workspace)) 58 12 2)
    $out += (KVLine "Algorithm" ([string]$script:Settings.Algorithm))
    $out += (KVLine "Strength" "$(StrengthBarColored $profile.Score)  $($profile.Category)")
    $out += (KVLine "Support" $support)
    $out += ""
    $out += (Mint "ROOT CA")
    $out += (KVLine "CN" (ShortText ([string]$root.SubjectCN) 58))
    $out += (KVLine "Valid" (ShortText ("$($root.NotBefore) -> $($root.NotAfter)") 58))
    $out += (KVLine "Key/Sig" (ShortText ("$($root.PubAlg) / $($root.SigAlg)") 58))
    $out += (KVLine "FP" (ShortText ([string]$root.FP) 58))
    $out += ""
    $out += (Mint "FILE SIGNER")
    $out += (KVLine "CN" (ShortText ([string]$sign.SubjectCN) 58))
    $out += (KVLine "Valid" (ShortText ("$($sign.NotBefore) -> $($sign.NotAfter)") 58))
    $out += (KVLine "Key/Sig" (ShortText ("$($sign.PubAlg) / $($sign.SigAlg)") 58))
    $out += (KVLine "FP" (ShortText ([string]$sign.FP) 58))
    $out += ""
    $out += (KVLine "Chain" $chain)
    $out += @(KVWrapLines "Last" ([string]$script:LastMessage) 58 12 2)

    $script:StatusCache = @($out)
    $script:StatusCacheAt = Get-Date
    return @($out)
}


function Render-MainMenu {
    param($Items,[int]$Selected)
    Update-FrameSize
    $lines = New-Object System.Collections.Generic.List[string]
    $status = @(Get-StatusLines)

    $lines.Add((FrameTop "PQC CERTIFICATE GUARD")) | Out-Null

    foreach ($b in (Get-PostQuantumBanner)) {
        $lines.Add((FrameBannerLine $b)) | Out-Null
    }

    $lines.Add((FrameCenter "PQC CERTIFICATE GUARD  |  PRIVATE PKI LAB  |  SAFE SCREENSHOT MODE")) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null
    $lines.Add((DualFrameLine (Mint "OPERATIONS") (Mint "LIVE CERTIFICATE STATUS"))) | Out-Null

    # Compact menu with details preserved: each operation uses two tight rows.
    # Row 1 is the action, row 2 is the wrapped hint. A viewport keeps the block tidy.
    $footerRows = 4
    $availableRows = [Math]::Max(6, $script:FrameRows - $lines.Count - $footerRows)
    $rowsPerItem = 2
    $visibleItemCount = [Math]::Max(1, [Math]::Floor($availableRows / $rowsPerItem))
    if ($visibleItemCount -gt $Items.Count) { $visibleItemCount = $Items.Count }

    $startIndex = 0
    if ($Selected -ge $visibleItemCount) { $startIndex = $Selected - $visibleItemCount + 1 }
    if (($startIndex + $visibleItemCount) -gt $Items.Count) { $startIndex = [Math]::Max(0, $Items.Count - $visibleItemCount) }

    $inner = $script:FrameWidth - 2
    $leftPadLen = 2
    $rightPadLen = 2
    $gapLen = 2
    $cw = $inner - $leftPadLen - $rightPadLen
    $leftCellWidth = [Math]::Floor(($cw - $gapLen) / 2)
    if ($leftCellWidth -lt 42) { $leftCellWidth = 42 }

    $row = 0
    for ($i = 0; $i -lt $visibleItemCount; $i++) {
        $idx = $startIndex + $i
        $it = $Items[$idx]
        $label = [string]$it.Label
        $hint = [string]$it.Hint
        $prefix = if ($idx -eq $Selected) { "▶ " } else { "  " }
        $num = if (-not [string]::IsNullOrWhiteSpace([string]$it.Shortcut)) { "[$($it.Shortcut)] " } else { "" }
        $captionPlain = ShortText ($prefix + $num + $label) $leftCellWidth
        $hintWrap = @(WrapPlainText -Text $hint -Width ([Math]::Max(20, $leftCellWidth - 4)) -MaxLines 1)
        $hintPlain = "    " + $(if ($hintWrap.Count -gt 0) { [string]$hintWrap[0] } else { "" })
        $hintPlain = ShortText $hintPlain $leftCellWidth

        if ($script:NmsEnabled) {
            # Real NMS on actual menu rows. Selected row remains readable, hint still breathes.
            $captionPlain = New-NmsText -Text $captionPlain -Index (20 + $idx) -Selected ($idx -eq $Selected) -Subtle
            $hintPlain = New-NmsText -Text $hintPlain -Index (80 + $idx) -Selected ($idx -eq $Selected) -Subtle
        }

        if ($idx -eq $Selected) {
            $left1 = Cb (FitPlain $captionPlain $leftCellWidth) 230 255 235 0 80 44
            $left2 = Pale (FitPlain $hintPlain $leftCellWidth)
        } else {
            $left1 = Pale $captionPlain
            $left2 = DimGreen $hintPlain
        }

        $right = if ($row -lt $status.Count) { $status[$row] } else { "" }
        $row++
        $lines.Add((DualFrameLine $left1 $right)) | Out-Null

        $right = if ($row -lt $status.Count) { $status[$row] } else { "" }
        $row++
        $lines.Add((DualFrameLine $left2 $right)) | Out-Null
    }

    while ($row -lt $status.Count -and $lines.Count -lt ($script:FrameRows - $footerRows)) {
        $right = $status[$row]; $row++
        $lines.Add((DualFrameLine "" $right)) | Out-Null
    }

    while ($lines.Count -lt ($script:FrameRows - 4)) { $lines.Add((FrameLine "")) | Out-Null }

    $nms = if ($script:NmsEnabled) { "NMS ON" } else { "NMS OFF" }
    $hint = ""
    if ($Selected -ge 0 -and $Selected -lt $Items.Count) { $hint = [string]$Items[$Selected].Hint }
    $pos = "item $($Selected + 1)/$($Items.Count)"
    $rangeText = if ($visibleItemCount -lt $Items.Count) { "visible $($startIndex + 1)-$($startIndex + $visibleItemCount)" } else { "all items visible" }

    $inner = $script:FrameWidth - 2
    $contentWidth = $inner - 6

    $gridText = Get-QuantumSignalText ([Math]::Max(20, $contentWidth - 16))
    $lines.Add((FrameLine ((DimGreen "  SIGNAL  ") + (BrightGreen $gridText)))) | Out-Null

    $actionPlain = if ([string]::IsNullOrWhiteSpace($hint)) { "Ready" } else { $hint }
    $actionPlain = ShortText $actionPlain ([Math]::Max(20, $contentWidth - 16))
    $lines.Add((FrameLine ((DimGreen "  ACTION  ") + (Pale $actionPlain)))) | Out-Null

    $keysPlain = "UP/DOWN move  ENTER open  ESC/Q quit  shortcuts 1-9/A/S/Q  N toggle NMS  |  $nms  |  $pos  |  $rangeText"
    $keysPlain = ShortText $keysPlain ([Math]::Max(20, $contentWidth - 16))
    $lines.Add((FrameLine ((DimGreen "  KEYS    ") + (Pale $keysPlain)))) | Out-Null
    $lines.Add((FrameBottom "POST-QUANTUM CERTIFICATE GUARD")) | Out-Null
    return @($lines)
}

function Invoke-MainMenu {
    $items = @(
        (New-MenuItem "Setup doctor" "doctor" "Check OpenSSL path, version, and PQC algorithm support." "1"),
        (New-MenuItem "Import existing certificate lab" "import" "Find existing lab certificates and use them in this workspace." "2"),
        (New-MenuItem "Generate Root CA" "root" "Create a private X.509 PQC root CA certificate and key." "3"),
        (New-MenuItem "Generate File-Signing Certificate" "signer" "Issue an operational file-signing certificate from the root CA." "4"),
        (New-MenuItem "Sign a file" "sign" "Create a detached ML-DSA / SLH-DSA signature for an artifact." "5"),
        (New-MenuItem "Verify signature and chain" "verify" "Verify the signed file and certificate chain." "6"),
        (New-MenuItem "Inspect certificates" "inspect" "Show detailed certificate metadata and strength profile." "7"),
        (New-MenuItem "Algorithm strength / support" "strength" "Compare ML-DSA and SLH-DSA strength and local OpenSSL support." "8"),
        (New-MenuItem "Screenshot proof card" "proof" "Display a full-page green proof card for sharing." "9"),
        (New-MenuItem "About this project" "about" "Explain the PQC certificate lab, safe usage, and trust boundaries." "a"),
        (New-MenuItem "Settings" "settings" "Change workspace, algorithm, lab names, context, and NMS." "s"),
        (New-MenuItem "Exit cleanly" "exit" "Close the console without unsafe key output." "q")
    )

    try { [Console]::CursorVisible = $false } catch { }
    Clear-PendingKeys
    $first = $true
    while ($true) {
        if ($first) { Clear-Host; $first = $false } else { try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host } }
        $render = @(Render-MainMenu -Items $items -Selected $script:MenuIndex)
        Write-FrameLines @($render)
        try {
            $deadline = (Get-Date).AddMilliseconds(140)
            while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 8 }
            if (-not [Console]::KeyAvailable) { if ($script:NmsEnabled) { $script:NmsTick++ }; continue }
            $key = [Console]::ReadKey($true)
        } catch {
            $choice = Read-Host "Choose"
            foreach ($it in $items) { if ($choice -eq $it.Shortcut) { return $it.Value } }
            continue
        }
        switch ($key.Key) {
            "UpArrow" { $script:MenuIndex--; if ($script:MenuIndex -lt 0) { $script:MenuIndex = $items.Count - 1 }; $script:NmsTick += 3; Clear-PendingKeys }
            "DownArrow" { $script:MenuIndex++; if ($script:MenuIndex -ge $items.Count) { $script:MenuIndex = 0 }; $script:NmsTick += 3; Clear-PendingKeys }
            "LeftArrow" { $script:MenuIndex--; if ($script:MenuIndex -lt 0) { $script:MenuIndex = $items.Count - 1 }; $script:NmsTick += 3; Clear-PendingKeys }
            "RightArrow" { $script:MenuIndex++; if ($script:MenuIndex -ge $items.Count) { $script:MenuIndex = 0 }; $script:NmsTick += 3; Clear-PendingKeys }
            "Enter" { return $items[$script:MenuIndex].Value }
            "Escape" { return "exit" }
            "Q" { return "exit" }
            "N" { $script:NmsEnabled = -not $script:NmsEnabled; $script:Settings.NmsEnabled = $script:NmsEnabled; Save-Settings; $script:LastMessage = "NMS set to $(if ($script:NmsEnabled) { 'ON' } else { 'OFF' })." }
            default {
                $ch = [string]$key.KeyChar
                if (-not [string]::IsNullOrWhiteSpace($ch)) {
                    foreach ($it in $items) { if ($ch.ToLowerInvariant() -eq ([string]$it.Shortcut).ToLowerInvariant()) { return $it.Value } }
                }
            }
        }
    }
}

# =============================================================================
# SCREENS / INPUT
# =============================================================================


function Show-LinesScreen([string]$Title,[string[]]$Content,[string]$Footer="Press ENTER to continue") {
    Update-FrameSize
    Clear-Host
    $script:LastScreenKey = ""
    $offset = 0
    try { [Console]::CursorVisible = $false } catch { }
    Clear-PendingKeys

    while ($true) {
        Update-FrameSize
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add((FrameTop $Title)) | Out-Null
        $lines.Add((FrameCenter "PQC CERTIFICATE GUARD")) | Out-Null
        $lines.Add((FrameLine "")) | Out-Null
        $lines.Add((FrameLine "")) | Out-Null

        $footerRows = 3
        $contentRows = [Math]::Max(6, $script:FrameRows - $lines.Count - $footerRows)
        $contentArray = @($Content)
        if ($contentArray.Count -le $contentRows) {
            $offset = 0
        } else {
            if ($offset -lt 0) { $offset = 0 }
            if ($offset -gt ($contentArray.Count - $contentRows)) { $offset = $contentArray.Count - $contentRows }
        }

        for ($i = 0; $i -lt $contentRows; $i++) {
            $idx = $offset + $i
            if ($idx -lt $contentArray.Count) {
                $lines.Add((FrameLine ([string]$contentArray[$idx]))) | Out-Null
            } else {
                $lines.Add((FrameLine "")) | Out-Null
            }
        }

        $inner = $script:FrameWidth - 2
        $contentWidth = $inner - 6
        $gridText = Get-QuantumSignalText ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  SIGNAL  ") + (BrightGreen $gridText)))) | Out-Null
        $scrollText = if ($contentArray.Count -gt $contentRows) { "UP/DOWN scroll  PGUP/PGDN page  ENTER/ESC back  N toggle NMS  |  row $($offset + 1)/$($contentArray.Count)" } else { "$Footer  |  ESC back  N toggle NMS" }
        $keysPlain = ShortText $scrollText ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  KEYS    ") + (Pale $keysPlain)))) | Out-Null
        $lines.Add((FrameBottom "POST-QUANTUM TRUST GRID")) | Out-Null

        try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host }
        Write-FrameLines @($lines)

        try {
            $deadline = (Get-Date).AddMilliseconds(140)
            while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 8 }
            if (-not [Console]::KeyAvailable) { if ($script:NmsEnabled) { $script:NmsTick++ }; continue }
            $key = [Console]::ReadKey($true)
        } catch {
            [void][Console]::ReadLine()
            $script:LastScreenKey = "Enter"
            return
        }

        switch ($key.Key) {
            "Enter" { $script:LastScreenKey = "Enter"; return }
            "Escape" { $script:LastScreenKey = "Escape"; return }
            "Q" { $script:LastScreenKey = "Q"; return }
            "UpArrow" { if ($offset -gt 0) { $offset-- }; Clear-PendingKeys }
            "DownArrow" { if ($offset -lt ($contentArray.Count - $contentRows)) { $offset++ }; Clear-PendingKeys }
            "PageUp" { $offset -= $contentRows; if ($offset -lt 0) { $offset = 0 }; Clear-PendingKeys }
            "PageDown" { $offset += $contentRows; if ($offset -gt ($contentArray.Count - $contentRows)) { $offset = [Math]::Max(0, $contentArray.Count - $contentRows) }; Clear-PendingKeys }
            "Home" { $offset = 0; Clear-PendingKeys }
            "End" { $offset = [Math]::Max(0, $contentArray.Count - $contentRows); Clear-PendingKeys }
            "N" { $script:NmsEnabled = -not $script:NmsEnabled; $script:Settings.NmsEnabled = $script:NmsEnabled; Save-Settings; $script:NmsTick += 4; Clear-PendingKeys }
        }
    }
}

function OperationFailed([string]$Title,[object]$Err) {
    $msg = if ($Err -is [System.Management.Automation.ErrorRecord]) { $Err.Exception.Message } else { [string]$Err }
    $where = ""
    $stack = ""
    if ($Err -is [System.Management.Automation.ErrorRecord]) {
        try { $where = [string]$Err.InvocationInfo.PositionMessage } catch { }
        try { $stack = [string]$Err.ScriptStackTrace } catch { }
    }
    $content = New-Object System.Collections.Generic.List[string]
    $content.Add((BadRed "  $Title")) | Out-Null
    $content.Add("") | Out-Null
    $content.Add((Pale "  $msg")) | Out-Null
    if (-not [string]::IsNullOrWhiteSpace($where)) {
        $content.Add("") | Out-Null
        $content.Add((DimGreen "  Location")) | Out-Null
        foreach ($l in @($where -split "`r?`n")) { if (-not [string]::IsNullOrWhiteSpace($l)) { $content.Add((Pale "  $(ShortText $l 132)")) | Out-Null } }
    }
    if (-not [string]::IsNullOrWhiteSpace($stack)) {
        $content.Add("") | Out-Null
        $content.Add((DimGreen "  Stack")) | Out-Null
        foreach ($l in @($stack -split "`r?`n" | Select-Object -First 3)) { if (-not [string]::IsNullOrWhiteSpace($l)) { $content.Add((Pale "  $(ShortText $l 132)")) | Out-Null } }
    }
    $content.Add("") | Out-Null
    $content.Add((DimGreen "  The tool caught the error instead of dumping raw PowerShell output.")) | Out-Null
    $content.Add((DimGreen "  This screen now includes command/location details for fixing.")) | Out-Null
    Show-LinesScreen -Title "OPERATION FAILED" -Content @($content)
}

function Read-Value([string]$Prompt,[string]$Default="") {
    Write-Host ""
    Write-Host (Emerald $Prompt) -NoNewline
    if (-not [string]::IsNullOrWhiteSpace($Default)) { Write-Host (DimGreen " [$Default]") -NoNewline }
    Write-Host (Pale ": ") -NoNewline
    $v = Read-Host
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v
}

function Find-DefaultSignatureFile {
    $sigDir = SigDir
    if (-not (Test-Path -LiteralPath $sigDir)) { return "" }
    $hit = @(Get-ChildItem -LiteralPath $sigDir -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.(pqc\.sig|mldsa87\.sig|sig)$' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1)
    if (@($hit).Count -gt 0) { return $hit[0].FullName }
    return ""
}

function Find-DefaultSignedFile {
    $candidate = [string]$script:Settings.LastSignedFile
    if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
        if (Test-IsSignatureFile $candidate) {
            $fromSig = Get-OriginalFileFromSignature $candidate
            if (-not [string]::IsNullOrWhiteSpace($fromSig) -and (Test-Path -LiteralPath $fromSig)) { return $fromSig }
        }
        return $candidate
    }

    $sig = Find-DefaultSignatureFile
    if (-not [string]::IsNullOrWhiteSpace($sig)) {
        $base = [System.IO.Path]::GetFileName($sig)
        $name = $base -replace '\.pqc\.sig$','' -replace '\.mldsa87\.sig$','' -replace '\.sig$',''
        $workspaceCandidate = Join-Path (Workspace) $name
        if (Test-Path -LiteralPath $workspaceCandidate) { return $workspaceCandidate }
        $currentCandidate = Join-Path (Get-Location).Path $name
        if (Test-Path -LiteralPath $currentCandidate) { return $currentCandidate }
    }

    foreach ($guess in @(
        (Join-Path (Workspace) 'test.txt'),
        (Join-Path (Get-Location).Path 'test.txt')
    )) {
        if (Test-Path -LiteralPath $guess) { return $guess }
    }

    return ""
}


function Get-InitialBrowseDirectory {
    param([string]$Default)

    try {
        if (-not [string]::IsNullOrWhiteSpace($Default)) {
            if (Test-Path -LiteralPath $Default -PathType Leaf) {
                return (Split-Path -Path (Resolve-Path -LiteralPath $Default).Path -Parent)
            }
            if (Test-Path -LiteralPath $Default -PathType Container) {
                return (Resolve-Path -LiteralPath $Default).Path
            }

            # If the default is a file path that does not exist yet, start in its parent folder.
            # This is important for signature selection, where the expected signature may not exist yet.
            $parent = [System.IO.Path]::GetDirectoryName($Default)
            if (-not [string]::IsNullOrWhiteSpace($parent) -and (Test-Path -LiteralPath $parent -PathType Container)) {
                return (Resolve-Path -LiteralPath $parent).Path
            }
        }

        $ws = Workspace
        if (-not [string]::IsNullOrWhiteSpace($ws) -and (Test-Path -LiteralPath $ws -PathType Container)) {
            return (Resolve-Path -LiteralPath $ws).Path
        }

        return (Get-Location).Path
    } catch {
        return (Get-Location).Path
    }
}


function Get-ParentDirectoryPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return "__DRIVES__"
    }

    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        $dir = [System.IO.DirectoryInfo]::new($full)
        if ($null -eq $dir.Parent) {
            return "__DRIVES__"
        }
        return $dir.Parent.FullName
    } catch {
        try {
            $parent = Split-Path -Path $Path -Parent
            if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $Path) { return "__DRIVES__" }
            return $parent
        } catch {
            return "__DRIVES__"
        }
    }
}

function New-BrowserItem {
    param(
        [string]$Kind,
        [string]$Name,
        [string]$Path,
        [string]$SortName
    )

    return [pscustomobject][ordered]@{
        Kind     = [string]$Kind
        Name     = [string]$Name
        Path     = [string]$Path
        SortName = [string]$SortName
    }
}

function Get-FileBrowserItems {
    param(
        [string]$CurrentDir,
        [string]$FileRegex = ".*"
    )

    # Use a plain PowerShell array, not a generic List. This avoids the
    # "Argument types do not match" crash that happened at return @($items)
    # on some Windows PowerShell builds.
    $items = @()

    if ($CurrentDir -eq "__DRIVES__") {
        foreach ($d in [System.IO.DriveInfo]::GetDrives()) {
            try {
                if ($d.IsReady) {
                    $label = if ([string]::IsNullOrWhiteSpace($d.VolumeLabel)) { [string]$d.Name } else { "$($d.Name)  $($d.VolumeLabel)" }
                    $items += (New-BrowserItem -Kind "drive" -Name $label -Path ([string]$d.RootDirectory.FullName) -SortName ([string]$d.Name))
                }
            } catch { }
        }
        return $items
    }

    try {
        if ([string]::IsNullOrWhiteSpace($CurrentDir) -or -not (Test-Path -LiteralPath $CurrentDir -PathType Container)) {
            $CurrentDir = (Get-Location).Path
        }

        $parent = Get-ParentDirectoryPath $CurrentDir
        if (-not [string]::IsNullOrWhiteSpace($parent) -and $parent -ne $CurrentDir) {
            $items += (New-BrowserItem -Kind "up" -Name "..  parent folder" -Path ([string]$parent) -SortName "000")
        } else {
            $items += (New-BrowserItem -Kind "driveRoot" -Name "..  choose drive" -Path "__DRIVES__" -SortName "000")
        }

        $dirs = @(Get-ChildItem -LiteralPath $CurrentDir -Directory -Force -ErrorAction SilentlyContinue | Sort-Object Name)
        foreach ($d in $dirs) {
            $items += (New-BrowserItem -Kind "dir" -Name ([string]$d.Name) -Path ([string]$d.FullName) -SortName ([string]$d.Name))
        }

        $files = @(Get-ChildItem -LiteralPath $CurrentDir -File -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $FileRegex } |
            Sort-Object Name)
        foreach ($f in $files) {
            $items += (New-BrowserItem -Kind "file" -Name ([string]$f.Name) -Path ([string]$f.FullName) -SortName ([string]$f.Name))
        }
    } catch {
        $items += (New-BrowserItem -Kind "error" -Name "Cannot read this folder" -Path ([string]$CurrentDir) -SortName "zzz")
    }

    return $items
}

function Select-FileFromBrowser {
    param(
        [string]$Title = "SELECT FILE",
        [string]$Prompt = "Choose a file",
        [string]$Default = "",
        [string]$FileRegex = ".*",
        [string]$FilterNote = "all files"
    )

    Update-FrameSize
    $current = Get-InitialBrowseDirectory $Default
    $selected = 0
    $offset = 0
    $manualMessage = "UP/DOWN move  ENTER open/select  BACKSPACE parent  D drives  P paste path  ESC cancel"

    try { [Console]::CursorVisible = $false } catch { }
    Clear-PendingKeys
    Clear-Host

    while ($true) {
        $items = @(Get-FileBrowserItems -CurrentDir $current -FileRegex $FileRegex)
        if ($items.Count -eq 0) {
            $items = @([pscustomobject]@{ Kind="empty"; Name="No matching files or folders"; Path=$current; SortName="" })
        }
        if ($selected -lt 0) { $selected = 0 }
        if ($selected -ge $items.Count) { $selected = $items.Count - 1 }

        $visibleRows = [Math]::Max(6, $script:FrameRows - 9)
        if ($selected -lt $offset) { $offset = $selected }
        if ($selected -ge ($offset + $visibleRows)) { $offset = $selected - $visibleRows + 1 }
        if ($offset -lt 0) { $offset = 0 }

        try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host }
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add((FrameTop $Title)) | Out-Null
        $lines.Add((FrameCenter "PQC CERTIFICATE FILE SYSTEM")) | Out-Null
        $lines.Add((FrameLine "")) | Out-Null
        $lines.Add((FrameLine ((Mint "  $Prompt") + (DimGreen "  |  filter: $FilterNote")))) | Out-Null
        $lines.Add((FrameLine ((DimGreen "  Folder ") + (Pale (ShortText (RedactPath $current) 128))))) | Out-Null
        if (-not [string]::IsNullOrWhiteSpace($Default)) {
            $lines.Add((FrameLine ((DimGreen "  Default") + (Pale ("  " + (ShortText (RedactPath $Default) 128)))))) | Out-Null
        } else {
            $lines.Add((FrameLine "")) | Out-Null
        }

        for ($row=0; $row -lt $visibleRows; $row++) {
            $idx = $offset + $row
            if ($idx -ge $items.Count) {
                $lines.Add((FrameLine "")) | Out-Null
                continue
            }
            $it = $items[$idx]
            $tag = switch ($it.Kind) {
                "file" { "FILE" }
                "dir" { "DIR " }
                "up" { "UP  " }
                "driveRoot" { "DRVS" }
                "drive" { "DRIV" }
                default { "INFO" }
            }
            $name = ShortText ([string]$it.Name) 118
            if ($script:NmsEnabled) { $name = New-NmsText -Text $name -Index (300 + $idx) -Selected ($idx -eq $selected) -Subtle }
            $plain = "  {0,3}. {1}  {2}" -f ($idx + 1), $tag, $name
            if ($script:NmsEnabled) {
                $plain = New-NmsText -Text $plain -Index (700 + $idx) -Selected ($idx -eq $selected) -Subtle
            }
            if ($idx -eq $selected) {
                $line = Cb (FitPlain $plain ($script:FrameWidth - 8)) 230 255 235 0 82 42
                $lines.Add((FrameLine $line)) | Out-Null
            } else {
                $colorName = if ($it.Kind -eq "file") { Pale $plain } elseif ($it.Kind -eq "dir" -or $it.Kind -eq "drive") { Mint $plain } else { DimGreen $plain }
                $lines.Add((FrameLine $colorName)) | Out-Null
            }
        }

        $pos = "item $($selected + 1) of $($items.Count)"
        $inner = $script:FrameWidth - 2
        $contentWidth = $inner - 6
        $gridText = Get-QuantumSignalText ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  SIGNAL  ") + (BrightGreen $gridText)))) | Out-Null
        $keysPlain = ShortText ("$manualMessage  |  N toggles NMS  |  $pos") ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  KEYS    ") + (Pale $keysPlain)))) | Out-Null
        $lines.Add((FrameBottom "SCROLLING FILE BROWSER")) | Out-Null
        Write-FrameLines @($lines)

        try {
            $deadline = (Get-Date).AddMilliseconds(140)
            while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 8 }
            if (-not [Console]::KeyAvailable) { if ($script:NmsEnabled) { $script:NmsTick++ }; continue }
        } catch { }

        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            "UpArrow" { $selected--; if ($selected -lt 0) { $selected = $items.Count - 1 }; Clear-PendingKeys }
            "DownArrow" { $selected++; if ($selected -ge $items.Count) { $selected = 0 }; Clear-PendingKeys }
            "PageUp" { $selected -= $visibleRows; if ($selected -lt 0) { $selected = 0 }; Clear-PendingKeys }
            "PageDown" { $selected += $visibleRows; if ($selected -ge $items.Count) { $selected = $items.Count - 1 }; Clear-PendingKeys }
            "Home" { $selected = 0; Clear-PendingKeys }
            "End" { $selected = $items.Count - 1; Clear-PendingKeys }
            "Backspace" {
                if ($current -eq "__DRIVES__") { $current = Get-InitialBrowseDirectory $Default }
                else {
                    $parent = Get-ParentDirectoryPath $current
                    if ([string]::IsNullOrWhiteSpace($parent)) { $current = "__DRIVES__" } else { $current = $parent }
                }
                $selected = 0; $offset = 0; Clear-PendingKeys
            }
            "D" { $current = "__DRIVES__"; $selected = 0; $offset = 0; Clear-PendingKeys }
            "P" {
                try { [Console]::CursorVisible = $true } catch { }
                Clear-Host
                $pasted = Read-Value "Paste full file path" $Default
                if (-not [string]::IsNullOrWhiteSpace($pasted) -and (Test-Path -LiteralPath $pasted -PathType Leaf)) {
                    try { [Console]::CursorVisible = $false } catch { }
                    return (Resolve-Path -LiteralPath $pasted).Path
                }
                if (-not [string]::IsNullOrWhiteSpace($pasted) -and (Test-Path -LiteralPath $pasted -PathType Container)) {
                    $current = (Resolve-Path -LiteralPath $pasted).Path
                    $selected = 0; $offset = 0
                }
                try { [Console]::CursorVisible = $false } catch { }
                Clear-Host
            }
            "Enter" {
                $it = $items[$selected]
                if ($it.Kind -eq "file") { return (Resolve-Path -LiteralPath $it.Path).Path }
                if ($it.Kind -eq "dir" -or $it.Kind -eq "up" -or $it.Kind -eq "drive" -or $it.Kind -eq "driveRoot") {
                    $current = [string]$it.Path
                    $selected = 0; $offset = 0; Clear-PendingKeys
                }
            }
            "Escape" { return "" }
            "N" { $script:NmsEnabled = -not $script:NmsEnabled; $script:Settings.NmsEnabled = $script:NmsEnabled; Save-Settings; $script:NmsTick += 4; Clear-PendingKeys }
        }
    }
}

function Choose-ExistingFile {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )

    $browserTitle = "SELECT FILE"
    if ($Prompt -match "sign") { $browserTitle = "SELECT FILE TO SIGN" }
    if ($Prompt -match "Signed file") { $browserTitle = "SELECT ORIGINAL FILE TO VERIFY" }
    $selected = Select-FileFromBrowser -Title $browserTitle -Prompt $Prompt -Default $Default -FileRegex ".*" -FilterNote "all files"
    if ([string]::IsNullOrWhiteSpace($selected)) {
        return ""
    }
    return $selected
}

function Choose-SignatureFile {
    param(
        [string]$Prompt,
        [string]$Default = ""
    )

    $selected = Select-FileFromBrowser -Title "SELECT SIGNATURE FILE" -Prompt $Prompt -Default $Default -FileRegex '\.(pqc\.sig|mldsa87\.sig|sig)$' -FilterNote ".pqc.sig / .mldsa87.sig / .sig"
    if ([string]::IsNullOrWhiteSpace($selected)) {
        return ""
    }
    return $selected
}

function Choose-Algorithm {
    Update-FrameSize
    Clear-Host
    $idx = 0
    while ($true) {
        try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host }
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add((FrameTop "SELECT PQC SIGNATURE ALGORITHM")) | Out-Null
        $lines.Add((FrameCenter "ML-DSA AND SLH-DSA X.509 SIGNING")) | Out-Null
        $lines.Add((FrameLine "")) | Out-Null
        $lines.Add((FrameLine "")) | Out-Null
        for ($i=0; $i -lt $script:Algorithms.Count; $i++) {
            $a = $script:Algorithms[$i]
            $mark = if ($i -eq $idx) { "  ▶ " } else { "    " }
            $support = if (Test-AlgorithmSupport $a.Name -FastOnly) { Good "SUPPORTED" } else { Amber "NOT FOUND" }
            $algText = [string]$a.Name
            $profileText = ShortText $a.Profile 122
            if ($script:NmsEnabled) {
                $algText = New-NmsText -Text $algText -Index (500 + $i) -Selected ($i -eq $idx) -Subtle
                $profileText = New-NmsText -Text $profileText -Index (540 + $i) -Selected ($i -eq $idx) -Subtle
            }
            $name = if ($i -eq $idx) { Cb (("{0,-24}" -f $algText)) 230 255 235 0 80 44 } else { Pale ("{0,-24}" -f $algText) }
            $line = "$(DimGreen $mark)$name $(StrengthBarColored $a.Score)  $(Pale $a.Category)  $support"
            $lines.Add((FrameLine $line)) | Out-Null
            $profileLine = "      $(DimGreen $profileText)"
            $lines.Add((FrameLine $profileLine)) | Out-Null
        }
        $footerRows = 3
        while ($lines.Count -lt ($script:FrameRows - $footerRows)) { $lines.Add((FrameLine "")) | Out-Null }
        $inner = $script:FrameWidth - 2
        $contentWidth = $inner - 6
        $gridText = Get-QuantumSignalText ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  SIGNAL  ") + (BrightGreen $gridText)))) | Out-Null
        $keysPlain = ShortText "UP/DOWN move  ENTER select  ESC back  N toggle NMS" ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  KEYS    ") + (Pale $keysPlain)))) | Out-Null
        $lines.Add((FrameBottom "POST-QUANTUM TRUST GRID")) | Out-Null
        Write-FrameLines @($lines)

        try {
            $deadline = (Get-Date).AddMilliseconds(140)
            while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 8 }
            if (-not [Console]::KeyAvailable) { if ($script:NmsEnabled) { $script:NmsTick++ }; continue }
        } catch { }

        $key = [Console]::ReadKey($true)
        switch ($key.Key) {
            "UpArrow" { $idx--; if ($idx -lt 0) { $idx = $script:Algorithms.Count - 1 } }
            "DownArrow" { $idx++; if ($idx -ge $script:Algorithms.Count) { $idx = 0 } }
            "Enter" { $script:Settings.Algorithm = $script:Algorithms[$idx].Name; $script:Settings.Context = "$(LabName)-$($script:Settings.Algorithm)-file-v1"; Save-Settings; return $script:Algorithms[$idx].Name }
            "Escape" { return $null }
            "N" { $script:NmsEnabled = -not $script:NmsEnabled; $script:Settings.NmsEnabled = $script:NmsEnabled; Save-Settings; $script:NmsTick += 4; Clear-PendingKeys }
        }
    }
}

# =============================================================================
# OPERATIONS
# =============================================================================

function Setup-Doctor {
    $content = New-Object System.Collections.Generic.List[string]
    foreach ($l in @(KVWrapLines "OpenSSL" (RedactPath (Get-OpenSslPath)) 120 12 2)) { $content.Add($l) | Out-Null }
    foreach ($l in @(KVWrapLines "Version" (Get-OpenSslVersion) 120 12 2)) { $content.Add($l) | Out-Null }
    foreach ($l in @(KVWrapLines "Workspace" (RedactPath ([string]$script:Settings.Workspace)) 120 12 2)) { $content.Add($l) | Out-Null }
    $content.Add((KVLine "Selected" ([string]$script:Settings.Algorithm))) | Out-Null
    $content.Add("") | Out-Null
    $content.Add((Mint "  Algorithm support check")) | Out-Null
    $content.Add((DimGreen "  Strength bar, NIST-style category, OpenSSL support, and practical profile.")) | Out-Null
    $content.Add("") | Out-Null

    foreach ($a in $script:Algorithms) {
        $ok = Test-AlgorithmSupport $a.Name
        $status = if ($ok) { Good "SUPPORTED" } else { Amber "NOT FOUND" }
        $bar = StrengthBarColored $a.Score
        $name = Pale ("{0,-23}" -f $a.Name)
        $category = DimGreen ("{0,-22}" -f $a.Category)
        $content.Add("    $name  $bar  $category  $status") | Out-Null
        $content.Add("        $(DimGreen (ShortText $a.Profile 122))") | Out-Null
    }

    Show-LinesScreen -Title "SETUP DOCTOR" -Content $content
}

function Import-ExistingLab {
    Ensure-Workspace
    $paths = Resolve-LabPaths
    $content = New-Object System.Collections.Generic.List[string]
    $content.Add((Mint "  Import existing certificate lab")) | Out-Null
    $content.Add((DimGreen "  This fixes path/name mismatches between older scripts and this tool.")) | Out-Null
    $content.Add("") | Out-Null
    $content.Add((KVLine "Workspace" (RedactPath ([string]$script:Settings.Workspace)))) | Out-Null
    $rootCrtText = if ($paths.RootCrt) { RedactPath $paths.RootCrt } else { "NOT FOUND" }
    $content.Add((KVLine "Root cert" $rootCrtText)) | Out-Null
    $signCrtText = if ($paths.SignCrt) { RedactPath $paths.SignCrt } else { "NOT FOUND" }
    $content.Add((KVLine "Signer cert" $signCrtText)) | Out-Null
    $rootKeyText = if ($paths.RootKey) { RedactPath $paths.RootKey } else { "NOT FOUND" }
    $content.Add((KVLine "Root key" $rootKeyText)) | Out-Null
    $signKeyText = if ($paths.SignKey) { RedactPath $paths.SignKey } else { "NOT FOUND" }
    $content.Add((KVLine "Signer key" $signKeyText)) | Out-Null
    $content.Add("") | Out-Null
    $content.Add((DimGreen "  v7 does not require old files to be renamed. It discovers and uses readable matching files.")) | Out-Null
    $script:LastMessage = "Import scan complete. Existing files are resolved dynamically."
    Clear-GuardCaches
    Show-LinesScreen -Title "IMPORT EXISTING LAB" -Content $content
}

function Write-CertConfig {
    param([string]$Path,[string]$Type)
    $content = if ($Type -eq "root") {
@"
[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_root_ca
string_mask = utf8only
[ dn ]
C = $($script:Settings.Country)
O = $($script:Settings.OrgName)
OU = $($script:Settings.RootOU)
CN = $($script:Settings.OrgName) $($script:Settings.Algorithm) Root CA 2026
[ v3_root_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
"@
    } else {
@"
[ v3_file_signing ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = codeSigning,emailProtection
"@
    }
    Set-Content -Path $Path -Value $content -Encoding ASCII
}

function Generate-RootCA {
    Ensure-Workspace
    $alg = Choose-Algorithm
    if (-not $alg) { return }
    if (-not (Test-AlgorithmSupport $alg)) { throw "OpenSSL does not appear to support $alg. Run Setup doctor and check OpenSSL 3.5+ PQC support." }
    $p = ExpectedPaths
    $cnf = Join-Path (ConfDir) "root-ca.cnf"
    Write-CertConfig -Path $cnf -Type "root"
    Invoke-OpenSsl -Args @("genpkey","-algorithm",$alg,"-out",$p.RootKey) | Out-Null
    Invoke-OpenSsl -Args @("req","-new","-x509","-days","3650","-key",$p.RootKey,"-out",$p.RootCrt,"-config",$cnf,"-extensions","v3_root_ca") | Out-Null
    $script:LastMessage = "Root CA generated: $alg"
    Clear-GuardCaches
    Show-LinesScreen -Title "ROOT CA GENERATED" -Content @(
        (KVLine "Algorithm" $alg),
        (KVLine "Root key" (RedactPath $p.RootKey)),
        (KVLine "Root cert" (RedactPath $p.RootCrt)),
        "",
        (Amber "  Keep the root CA private key offline and protected.")
    )
}

function Generate-FileSigner {
    Ensure-Workspace
    $paths = Resolve-LabPaths
    if (-not $paths.RootCrt -or -not $paths.RootKey) { throw "Root CA certificate/key not found. Generate or import the root CA first." }
    $alg = [string]$script:Settings.Algorithm
    if (-not (Test-AlgorithmSupport $alg)) { throw "OpenSSL does not appear to support $alg." }
    $p = ExpectedPaths
    $ext = Join-Path (ConfDir) "file-signing.ext.cnf"
    Write-CertConfig -Path $ext -Type "signer"
    $subj = "/C=$($script:Settings.Country)/O=$($script:Settings.LabName)/OU=$($script:Settings.SignerOU)/CN=$($script:Settings.LabName) $alg File Signing 2026"
    Invoke-OpenSsl -Args @("genpkey","-algorithm",$alg,"-out",$p.SignKey) | Out-Null
    Invoke-OpenSsl -Args @("req","-new","-key",$p.SignKey,"-out",$p.Csr,"-subj",$subj) | Out-Null
    Invoke-OpenSsl -Args @("x509","-req","-in",$p.Csr,"-CA",$paths.RootCrt,"-CAkey",$paths.RootKey,"-CAcreateserial","-out",$p.SignCrt,"-days","730","-extfile",$ext,"-extensions","v3_file_signing") | Out-Null
    Invoke-OpenSsl -Args @("x509","-in",$p.SignCrt,"-pubkey","-noout","-out",$p.SignPub) | Out-Null
    $script:LastMessage = "File-signing certificate generated: $alg"
    Clear-GuardCaches
    Show-LinesScreen -Title "FILE-SIGNING CERTIFICATE GENERATED" -Content @(
        (KVLine "Algorithm" $alg),
        (KVLine "Signer key" (RedactPath $p.SignKey)),
        (KVLine "Signer cert" (RedactPath $p.SignCrt)),
        (KVLine "Signer pub" (RedactPath $p.SignPub)),
        "",
        (DimGreen "  This key is for operational signing. The root CA only certifies the signer.")
    )
}

function Sign-File {
    Ensure-Workspace
    $paths = Resolve-LabPaths
    if (-not $paths.SignKey) { throw "Signer private key not found. Generate or import a file-signing certificate first." }
    Clear-Host
    $defaultFile = Find-DefaultSignedFile
    $file = Choose-ExistingFile "File to sign" $defaultFile
    if ([string]::IsNullOrWhiteSpace($file)) { $script:LastMessage = "Signing cancelled."; return }
        $fileDir = Split-Path -Path $file -Parent
    if ([string]::IsNullOrWhiteSpace($fileDir)) { $fileDir = (Get-Location).Path }
    $sig = Join-Path $fileDir ((Split-Path -Leaf $file) + ".pqc.sig")
    $ctx = [string]$script:Settings.Context
    Invoke-OpenSsl -Args @("pkeyutl","-sign","-in",$file,"-inkey",$paths.SignKey,"-out",$sig,"-pkeyopt","context-string:$ctx") | Out-Null
    $script:Settings.LastSignedFile = $file
    $script:Settings.LastSignatureFile = $sig
    Save-Settings
    $script:LastMessage = "Signed file: $(Split-Path -Leaf $file)"
    Clear-GuardCaches
    Show-LinesScreen -Title "FILE SIGNED" -Content @(
        (KVLine "File" (RedactPath $file)),
        (KVLine "Signature" (RedactPath $sig)),
        (KVLine "Output" "signature saved beside the selected file"),
        (KVLine "Context" $ctx),
        (KVLine "Size" "$((Get-Item -LiteralPath $sig).Length) bytes")
    )
}


function Test-IsSignatureFile {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $leaf = [System.IO.Path]::GetFileName([string]$Path)
    if ([string]::IsNullOrWhiteSpace($leaf)) { return $false }
    return ($leaf.EndsWith(".pqc.sig", [System.StringComparison]::OrdinalIgnoreCase) -or
            $leaf.EndsWith(".mldsa87.sig", [System.StringComparison]::OrdinalIgnoreCase) -or
            $leaf.EndsWith(".sig", [System.StringComparison]::OrdinalIgnoreCase))
}

function Get-OriginalFileFromSignature {
    param([string]$Signature)
    if ([string]::IsNullOrWhiteSpace($Signature)) { return "" }
    $dir = Split-Path -Path $Signature -Parent
    $leaf = Split-Path -Leaf $Signature
    $base = $leaf
    if ($base.EndsWith(".pqc.sig", [System.StringComparison]::OrdinalIgnoreCase)) {
        $base = $base.Substring(0, $base.Length - ".pqc.sig".Length)
    } elseif ($base.EndsWith(".mldsa87.sig", [System.StringComparison]::OrdinalIgnoreCase)) {
        $base = $base.Substring(0, $base.Length - ".mldsa87.sig".Length)
    } elseif ($base.EndsWith(".sig", [System.StringComparison]::OrdinalIgnoreCase)) {
        $base = $base.Substring(0, $base.Length - ".sig".Length)
    }
    if ([string]::IsNullOrWhiteSpace($dir)) { return $base }
    return (Join-Path $dir $base)
}

function Add-WrappedOutputLines {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Text,
        [int]$Width = 122,
        [string[]]$KnownPaths = @()
    )

    $clean = [string]$Text
    foreach ($p in @($KnownPaths)) {
        if (-not [string]::IsNullOrWhiteSpace($p)) {
            $clean = $clean.Replace($p, (RedactPath $p))
        }
    }

    if ([string]::IsNullOrWhiteSpace($clean)) {
        $List.Add((DimGreen "  N/A")) | Out-Null
        return
    }

    foreach ($line in @($clean -split "`r?`n")) {
        foreach ($w in @(WrapPlainText -Text $line -Width $Width -MaxLines 0)) {
            if (-not [string]::IsNullOrWhiteSpace($w)) { $List.Add((Pale "  $w")) | Out-Null }
        }
    }
}

function Find-SignatureForFile {
    param([string]$File)

    if ([string]::IsNullOrWhiteSpace($File)) { return "" }

    $leaf = Split-Path -Leaf $File
    $dir = Split-Path -Parent $File
    $sigDir = SigDir
    $candidates = New-Object System.Collections.Generic.List[string]

    # Prefer signatures stored beside the signed file.
    $candidates.Add((Join-Path $dir ($leaf + ".pqc.sig"))) | Out-Null
    $candidates.Add((Join-Path $dir ($leaf + ".mldsa87.sig"))) | Out-Null
    $candidates.Add((Join-Path $dir ($leaf + ".sig"))) | Out-Null
    # Also support older versions that placed signatures in the workspace sig folder.
    $candidates.Add((Join-Path $sigDir ($leaf + ".pqc.sig"))) | Out-Null
    $candidates.Add((Join-Path $sigDir ($leaf + ".mldsa87.sig"))) | Out-Null
    $candidates.Add((Join-Path $sigDir ($leaf + ".sig"))) | Out-Null

    $lastSig = [string]$script:Settings.LastSignatureFile
    if (-not [string]::IsNullOrWhiteSpace($lastSig)) {
        $lastLeaf = Split-Path -Leaf $lastSig
        if ($lastLeaf -like "$leaf*") {
            $candidates.Insert(0, $lastSig)
        }
    }

    foreach ($c in @($candidates)) {
        if (-not [string]::IsNullOrWhiteSpace($c) -and (Test-Path -LiteralPath $c)) {
            return $c
        }
    }

    return (Join-Path $sigDir ($leaf + ".pqc.sig"))
}

function Test-SignatureLikelyMatchesFile {
    param(
        [string]$File,
        [string]$Signature
    )

    if ([string]::IsNullOrWhiteSpace($File) -or [string]::IsNullOrWhiteSpace($Signature)) { return $false }
    $leaf = Split-Path -Leaf $File
    $sigLeaf = Split-Path -Leaf $Signature
    return ($sigLeaf -like "$leaf*")
}


function Verify-File {
    Ensure-Workspace
    $paths = Resolve-LabPaths
    if (-not $paths.RootCrt -or -not $paths.SignCrt) { throw "Certificate chain is incomplete." }

    # Always extract the public key from the currently selected signer certificate.
    # This avoids stale .pub.pem files causing false signature failures after a new signer cert is generated or imported.
    $verifyPub = (ExpectedPaths).SignPub
    Invoke-OpenSsl -Args @("x509","-in",$paths.SignCrt,"-pubkey","-noout","-out",$verifyPub) | Out-Null
    $paths = Resolve-LabPaths

    Clear-Host
    $defaultFile = Find-DefaultSignedFile
    $file = Choose-ExistingFile "Signed file" $defaultFile
    if ([string]::IsNullOrWhiteSpace($file)) { $script:LastMessage = "Verification cancelled."; return }

    $sig = ""
    if (Test-IsSignatureFile $file) {
        # User selected the detached signature as the file. Recover the original file beside it.
        $selectedSignature = $file
        $maybeOriginal = Get-OriginalFileFromSignature $selectedSignature
        if (-not [string]::IsNullOrWhiteSpace($maybeOriginal) -and (Test-Path -LiteralPath $maybeOriginal)) {
            $file = $maybeOriginal
            $sig = $selectedSignature
        } else {
            Show-LinesScreen -Title "VERIFY PAIR NEEDED" -Content @(
                (Amber "  You selected a signature file as the artifact."),
                (KVLine "Signature" (RedactPath $selectedSignature)),
                (KVLine "Expected file" (RedactPath $maybeOriginal)),
                "",
                (DimGreen "  Keep the .pqc.sig beside the original file, then select the original file for verification.")) | Out-Null
            $script:LastMessage = "Verification cancelled. Original file was not found beside signature."
            return
        }
    }

    if ([string]::IsNullOrWhiteSpace($sig)) {
        $sigDefault = Find-SignatureForFile $file
        $sig = Choose-SignatureFile "Signature file for selected file" $sigDefault
    }

    if ([string]::IsNullOrWhiteSpace($sig)) { $script:LastMessage = "Verification cancelled."; return }
    if (-not (Test-Path -LiteralPath $sig)) { throw "Signature not found: $sig" }

    $chain = Invoke-OpenSsl -Args @("verify","-CAfile",$paths.RootCrt,$paths.SignCrt) -NoThrow
    $chainStatus = if ($chain.ExitCode -eq 0) { "VALID" } else { "FAILED" }
    $likelyPair = Test-SignatureLikelyMatchesFile -File $file -Signature $sig

    if (-not $likelyPair) {
        $vr = [pscustomobject]@{
            ExitCode = 997
            Output = "Signature check skipped: selected signature filename does not match the selected file. Sign this file first, or choose the matching .pqc.sig file."
            Exe = ""
            Command = ""
        }
        $sigStatus = "NOT CHECKED"
    } else {
        $vr = Invoke-OpenSsl -Args @("pkeyutl","-verify","-in",$file,"-pubin","-inkey",$verifyPub,"-sigfile",$sig,"-pkeyopt","context-string:$($script:Settings.Context)") -NoThrow
        $sigStatus = if ($vr.ExitCode -eq 0) { "VALID" } else { "FAILED" }
    }

    if ($sigStatus -eq "VALID") {
        $script:Settings.LastSignedFile = $file
        $script:Settings.LastSignatureFile = $sig
        Save-Settings
    }

    $script:LastMessage = "Verification: chain $chainStatus, signature $sigStatus"
    Clear-GuardCaches

    $explain = New-Object System.Collections.Generic.List[string]
    if ($sigStatus -ne "VALID") {
        if (-not $likelyPair) {
            $explain.Add((Amber "  The selected signature filename does not look bound to the selected file.")) | Out-Null
            $explain.Add((DimGreen "  A detached signature verifies only the exact file bytes, the exact public key, and the exact context string.")) | Out-Null
            $explain.Add((DimGreen "  A detached signature made for test.txt cannot verify another file. Sign the selected file first, then verify the matching .pqc.sig.")) | Out-Null
        } else {
            $explain.Add((Amber "  Signature failed. The file, signature, public key, or context string does not match.")) | Out-Null
            $explain.Add((DimGreen "  Check that the signer certificate, signer private key, and context string belong to the same lab generation.")) | Out-Null
        }
    } else {
        $explain.Add((Good "  Signature is valid for this file, signer public key, and context string.")) | Out-Null
    }
    if ($chainStatus -ne "VALID") {
        $explain.Add((Amber "  Chain is not valid against the current root CA.")) | Out-Null
        $explain.Add((DimGreen ("  " + (Get-ChainDiagnosis)))) | Out-Null
    }

    $content = New-Object System.Collections.Generic.List[string]
    $content.Add((KVLine "Chain" $chainStatus)) | Out-Null
    $content.Add((KVLine "Signature" $sigStatus)) | Out-Null
    $content.Add((KVLine "File" (RedactPath $file))) | Out-Null
    $content.Add((KVLine "Signature file" (RedactPath $sig))) | Out-Null
    $content.Add((KVLine "Public key" (RedactPath $verifyPub))) | Out-Null
    $content.Add((KVLine "Context" ([string]$script:Settings.Context))) | Out-Null
    $content.Add((KVLine "Likely pair" $(if ($likelyPair) { "YES" } else { "NO, filename mismatch" }))) | Out-Null
    $content.Add("") | Out-Null
    foreach ($e in @($explain)) { $content.Add($e) | Out-Null }
    $content.Add("") | Out-Null
    $content.Add((DimGreen "  OpenSSL chain output:")) | Out-Null
    Add-WrappedOutputLines -List $content -Text $chain.Output -Width 122 -KnownPaths @($paths.RootCrt,$paths.SignCrt,$paths.RootKey,$paths.SignKey,$verifyPub,$file,$sig)
    $content.Add((DimGreen "  OpenSSL signature output:")) | Out-Null
    Add-WrappedOutputLines -List $content -Text $vr.Output -Width 122 -KnownPaths @($paths.RootCrt,$paths.SignCrt,$paths.RootKey,$paths.SignKey,$verifyPub,$file,$sig)

    Show-LinesScreen -Title "VERIFICATION RESULT" -Content $content
}

function Inspect-Certificates {
    $paths = Resolve-LabPaths
    $root = Get-CertInfo $paths.RootCrt
    $sign = Get-CertInfo $paths.SignCrt
    $content = @(
        (Mint "  ROOT CA CERTIFICATE"),
        (KVLine "Path" $(if ($paths.RootCrt) { RedactPath $paths.RootCrt } else { "NOT FOUND" })),
        (KVLine "Subject CN" $root.SubjectCN),
        (KVLine "Issuer CN" $root.IssuerCN),
        (KVLine "Serial" $root.Serial),
        (KVLine "Valid" "$($root.NotBefore) -> $($root.NotAfter)"),
        (KVLine "Public key" "$($root.PubAlg)    Cert sig $($root.SigAlg)"),
        (KVLine "Strength" (Get-StrengthText $root.PubAlg)),
        (KVLine "SHA256 FP" $root.FP),
        "",
        (Mint "  FILE-SIGNING CERTIFICATE"),
        (KVLine "Path" $(if ($paths.SignCrt) { RedactPath $paths.SignCrt } else { "NOT FOUND" })),
        (KVLine "Subject CN" $sign.SubjectCN),
        (KVLine "Issuer CN" $sign.IssuerCN),
        (KVLine "Serial" $sign.Serial),
        (KVLine "Valid" "$($sign.NotBefore) -> $($sign.NotAfter)"),
        (KVLine "Public key" "$($sign.PubAlg)    Cert sig $($sign.SigAlg)"),
        (KVLine "Strength" (Get-StrengthText $sign.PubAlg)),
        (KVLine "SHA256 FP" $sign.FP),
        "",
        (Mint "  CHAIN CHECK"),
        (KVLine "Status" (Get-ChainStatus)),
        (KVLine "Diagnosis" (Get-ChainDiagnosis))
    )
    Show-LinesScreen -Title "CERTIFICATE INSPECTION" -Content $content
}

function Show-Strength {
    $content = New-Object System.Collections.Generic.List[string]
    $content.Add((KVLine "OpenSSL" (ShortText (Get-OpenSslVersion) 122))) | Out-Null
    $content.Add((KVLine "Selected" ([string]$script:Settings.Algorithm))) | Out-Null
    $content.Add("") | Out-Null
    $content.Add((Mint "  Algorithm strength / support")) | Out-Null
    $content.Add((DimGreen "  Same strength scale used by Setup Doctor, About, Live Status, and Proof Card.")) | Out-Null
    $content.Add("") | Out-Null
    foreach ($a in $script:Algorithms) {
        $ok = Test-AlgorithmSupport $a.Name
        $status = if ($ok) { Good "SUPPORTED" } else { Amber "NOT FOUND" }
        $bar = StrengthBarColored $a.Score
        $name = Pale ("{0,-23}" -f $a.Name)
        $category = DimGreen ("{0,-22}" -f $a.Category)
        $content.Add("    $name  $bar  $category  $status") | Out-Null
        $content.Add("        $(DimGreen (ShortText $a.Profile 122))") | Out-Null
    }
    Show-LinesScreen -Title "ALGORITHM STRENGTH / SUPPORT" -Content $content
}

function Show-ProofCard {
    $paths = Resolve-LabPaths
    $root = Get-CertInfo $paths.RootCrt
    $sign = Get-CertInfo $paths.SignCrt
    $chain = Get-ChainStatus
    $rootProfile = Get-AlgorithmProfile $root.PubAlg
    $signProfile = Get-AlgorithmProfile $sign.PubAlg
    $lastFile = [string]$script:Settings.LastSignedFile
    $lastSig = [string]$script:Settings.LastSignatureFile
    $fileHash = if (-not [string]::IsNullOrWhiteSpace($lastFile) -and (Test-Path -LiteralPath $lastFile)) { ShortHex ((Get-FileHash -Algorithm SHA256 -Path $lastFile).Hash) } else { "N/A" }
    $sigHash = if (-not [string]::IsNullOrWhiteSpace($lastSig) -and (Test-Path -LiteralPath $lastSig)) { ShortHex ((Get-FileHash -Algorithm SHA256 -Path $lastSig).Hash) } else { "N/A" }

    Clear-Host
    $w = [Math]::Min([Console]::WindowWidth, 158)
    if ($w -lt 120) { $w = 120 }
    $oldW = $script:FrameWidth
    $script:FrameWidth = $w
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add((FrameTop "X.509 PQC / ML-DSA + SLH-DSA")) | Out-Null
    $lines.Add((FrameCenter "POST-QUANTUM SIGNING MILESTONE")) | Out-Null
    $lines.Add((FrameCenter "PUBLIC CERTIFICATE METADATA ONLY  |  SAFE SCREENSHOT VIEW")) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null

    $lines.Add((DualFrameLine (Mint "  WHAT THIS IS") (Mint "  WHY IT MATTERS"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Purpose" "private PQC X.509 signing lab") (KVLine "Quantum risk" "RSA/ECC are vulnerable to Shor-scale QC"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Protects" "integrity, authenticity, signer proof") (KVLine "PQC role" "digital signatures beyond RSA/ECC model"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Boundary" "not public browser/WebPKI trust") (KVLine "Evidence" "chain, algorithm, hash, validation"))) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null

    $lines.Add((DualFrameLine (Mint "  ROOT CA") (Mint "  FILE-SIGNING CERTIFICATE"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Subject" (ShortText $root.SubjectCN 52)) (KVLine "Subject" (ShortText $sign.SubjectCN 52)))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Issuer" (ShortText $root.IssuerCN 52)) (KVLine "Issuer" (ShortText $sign.IssuerCN 52)))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Valid until" (ShortText $root.NotAfter 52)) (KVLine "Valid until" (ShortText $sign.NotAfter 52)))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Key/Sig" "$($root.PubAlg) / $($root.SigAlg)") (KVLine "Key/Sig" "$($sign.PubAlg) / $($sign.SigAlg)"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Strength" "$(StrengthBarColored $rootProfile.Score) $($rootProfile.Category)") (KVLine "Strength" "$(StrengthBarColored $signProfile.Score) $($signProfile.Category)"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "FP" $root.FP) (KVLine "FP" $sign.FP))) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null

    $lines.Add((DualFrameLine (Mint "  SIGNED ARTIFACT") (Mint "  VALIDATION"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "File" (RedactPath $lastFile)) (KVLine "Chain" $chain))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Signature" (RedactPath $lastSig)) (KVLine "Context" (ShortText ([string]$script:Settings.Context) 52)))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "File hash" $fileHash) (KVLine "Private key" "not shown, not exported"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "Sig hash" $sigHash) (KVLine "Mode" "detached PQC signature"))) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null

    $lines.Add((DualFrameLine (Mint "  ALGORITHM GUIDE") (Mint "  SAFE INTERPRETATION"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "ML-DSA" "lattice-based NIST signature family") (KVLine "Magnitude" "PQC certificate chain built and verified"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "SLH-DSA" "hash-based conservative signature family") (KVLine "Scope" "private lab/internal trust anchor"))) | Out-Null
    $lines.Add((DualFrameLine (KVLine "87/65/44" "Category 5 / 3 / 2 style profiles") (KVLine "Not claiming" "public WebPKI or universal adoption"))) | Out-Null
    $lines.Add((FrameLine "")) | Out-Null

    $lines.Add((FrameLine ((Mint "  SCREENSHOT SAFETY")))) | Out-Null
    $lines.Add((FrameLine ((DimGreen "  Public to share ") + (Pale "certificate metadata, fingerprints, validation status, artifact hashes, and context string")))) | Out-Null
    $lines.Add((FrameLine ((DimGreen "  Keep private    ") + (Pale "root CA private key, signer private key, passphrases, secret material, revocation secrets")))) | Out-Null
    while ($lines.Count -lt ([Console]::WindowHeight - 2)) { $lines.Add((FrameLine "")) | Out-Null }
    $lines.Add((FrameBottom "QUANTUM-SAFE PUBLIC METADATA")) | Out-Null
    Write-FrameLines @($lines)
    $script:FrameWidth = $oldW
    [void][Console]::ReadLine()
}


function Show-AboutPage {
    Update-FrameSize
    Clear-Host
    $script:LastScreenKey = ""
    try { [Console]::CursorVisible = $false } catch { }
    Clear-PendingKeys

    while ($true) {
        Update-FrameSize
        try { $paths = Resolve-LabPaths } catch { $paths = $null }
        $alg = [string]$script:Settings.Algorithm
        $profile = Get-AlgorithmProfile $alg
        $support = Get-SafeValue { if (Test-AlgorithmSupport $alg -FastOnly) { "SUPPORTED" } else { "CHECK NEEDED" } } "CHECK NEEDED"
        $chain = Get-SafeValue { Get-ChainStatus } "CHECK NEEDED"
        $chainNote = Get-SafeValue { Get-ChainDiagnosis } "Chain diagnosis unavailable."
        $root = Get-SafeValue { Get-CertInfo $paths.RootCrt } $null
        $sign = Get-SafeValue { Get-CertInfo $paths.SignCrt } $null
        if ($null -eq $root -or ($root -is [string])) { $root = [pscustomobject]@{ SubjectCN="MISSING"; NotAfter="N/A"; PubAlg="N/A"; SigAlg="N/A"; FP="N/A" } }
        if ($null -eq $sign -or ($sign -is [string])) { $sign = [pscustomobject]@{ SubjectCN="MISSING"; NotAfter="N/A"; PubAlg="N/A"; SigAlg="N/A"; FP="N/A" } }

        $inner = $script:FrameWidth - 2
        $leftPad = 2
        $rightPad = 2
        $gap = 3
        $cw = $inner - $leftPad - $rightPad
        $cellWidth = [Math]::Floor(($cw - $gap) / 2)
        if ($cellWidth -lt 44) { $cellWidth = 44 }
        $termWidth = 14
        $valueWidth = [Math]::Max(18, $cellWidth - $termWidth - 2)

        function AboutTermText { param([string]$Term) return (PadAnsi (DimGreen $Term) $termWidth) }
        function AboutCell {
            param([string]$Term,[string]$Value,[int]$MaxLines = 1,[switch]$UseNms)
            $v = if ($null -eq $Value) { "N/A" } else { [string]$Value }
            if ($UseNms -and $script:NmsEnabled) { $v = New-NmsText -Text $v -Index (($Term.Length * 17) + $script:NmsTick) -Selected $true -Subtle }
            $parts = @(WrapPlainText -Text $v -Width $valueWidth -MaxLines $MaxLines)
            $out = New-Object System.Collections.Generic.List[string]
            for ($i=0; $i -lt $parts.Count; $i++) {
                $t = if ($i -eq 0) { AboutTermText $Term } else { AboutTermText "" }
                $out.Add($t + " " + (Pale ([string]$parts[$i]))) | Out-Null
            }
            if ($out.Count -eq 0) { $out.Add("") | Out-Null }
            return [string[]]$out.ToArray()
        }
        function AboutRaw { param([string]$Term,[string]$AnsiValue) return [string[]]@((AboutTermText $Term) + " " + $AnsiValue) }
        function AboutHeader { param([string]$Text) return [string[]]@((Mint "  $Text")) }
        function AboutAlg {
            param([string]$Name,[int]$Score,[string]$Meaning)
            $nameColored = PadAnsi (Emerald $Name) $termWidth
            return [string[]]@($nameColored + " " + (StrengthBarColored $Score) + "  " + (Pale $Meaning))
        }
        function AddAboutRows {
            param([System.Collections.Generic.List[object]]$Target,[string[]]$Left,[string[]]$Right)
            $la = @($Left)
            $ra = @($Right)
            $max = [Math]::Max($la.Count, $ra.Count)
            for ($i=0; $i -lt $max; $i++) {
                $l = if ($i -lt $la.Count) { [string]$la[$i] } else { "" }
                $r = if ($i -lt $ra.Count) { [string]$ra[$i] } else { "" }
                $Target.Add([pscustomobject]@{ L=$l; R=$r }) | Out-Null
            }
        }

        $flatRows = New-Object System.Collections.Generic.List[object]
        AddAboutRows $flatRows (AboutHeader "QUANTUM-SAFE DICTIONARY") (AboutHeader "LIVE LAB STATE")
        AddAboutRows $flatRows (AboutCell "Companion" "certificate-side twin to OpenPGP Quantum Guard" 1) (AboutCell "Algorithm" $alg 1 -UseNms)
        AddAboutRows $flatRows (AboutCell "PQC" "signatures after the RSA/ECC comfort zone" 1) (AboutRaw "Strength" ((StrengthBarColored $profile.Score) + "  " + (Pale $profile.Category)))
        AddAboutRows $flatRows (AboutCell "Root CA" "private trust anchor, not a browser CA" 1) (AboutCell "Support" $support 1)
        AddAboutRows $flatRows (AboutCell "Signer cert" "daily artifact identity issued by the root" 1) (AboutCell "Chain" $chain 1)
        AddAboutRows $flatRows (AboutCell "Detached sig" ".pqc.sig proves the exact bytes beside it" 1) (AboutCell "Diagnosis" $chainNote 2)
        AddAboutRows $flatRows (AboutCell "Context" "domain separator bound into signature checks" 1) (AboutCell "Workspace" (RedactPath ([string]$script:Settings.Workspace)) 1)
        AddAboutRows $flatRows (AboutCell "Evidence" "chain, algorithm, fingerprint, hash, context" 1) (AboutCell "Signer CN" ([string]$sign.SubjectCN) 1)
        AddAboutRows $flatRows (AboutCell "Hash-lock" "same file bytes or verification fails" 1) (AboutCell "Root CN" ([string]$root.SubjectCN) 1)

        AddAboutRows $flatRows (AboutHeader "ALGORITHM MAP") (AboutHeader "THREAT TRANSLATION")
        AddAboutRows $flatRows (AboutAlg "ML-DSA-87" 10 "Category 5, high-strength lattice") (AboutCell "Quantum risk" "Shor-scale QC breaks RSA/ECC assumptions" 1)
        AddAboutRows $flatRows (AboutAlg "ML-DSA-65" 8 "Category 3, balanced lattice") (AboutCell "PQC role" "authenticity and integrity beyond RSA/ECC" 1)
        AddAboutRows $flatRows (AboutAlg "ML-DSA-44" 6 "Category 2, smaller lattice") (AboutCell "Not secrecy" "signing proves origin, it does not encrypt" 1)
        AddAboutRows $flatRows (AboutAlg "SLH-DSA-256" 10 "hash-based conservative tier") (AboutCell "Boundary" "private lab/internal trust anchor" 1)
        AddAboutRows $flatRows (AboutAlg "SLH-DSA-192" 8 "hash-based Category 3 tier") (AboutCell "Mismatch" "old signer plus new root must fail" 1)
        AddAboutRows $flatRows (AboutAlg "SLH-DSA-128" 5 "baseline hash-based tier") (AboutCell "s / f" "s is smaller, f is faster" 1)

        AddAboutRows $flatRows (AboutHeader "OPERATIONAL SPELLBOOK") (AboutHeader "SAFE SCREENSHOT RULES")
        AddAboutRows $flatRows (AboutCell "1 Root" "create or import a guarded PQC root CA" 1) (AboutCell "Share" "cert metadata, fingerprints, hashes, status" 1)
        AddAboutRows $flatRows (AboutCell "2 Issue" "generate signer cert from current root" 1) (AboutCell "Hide" "private keys, passphrases, revocation secrets" 1)
        AddAboutRows $flatRows (AboutCell "3 Sign" "write signature beside the artifact" 1) (AboutCell "Redaction" "local folders become [local path hidden]" 1)
        AddAboutRows $flatRows (AboutCell "4 Verify" "chain, public key, artifact, sig, context" 1) (AboutCell "Meaning" "verifiable milestone, not universal CA claim" 1)
        AddAboutRows $flatRows (AboutCell "5 Proof" "public metadata card for sharing" 1) (AboutCell "Failure" "wrong file, key, context, or root fails" 1)

        AddAboutRows $flatRows (AboutHeader "WHAT IT IS") (AboutHeader "WHAT IT IS NOT")
        AddAboutRows $flatRows (AboutCell "It is" "a green-grid private PKI lab for PQC signing" 1) (AboutCell "Not WebPKI" "no browser or public TLS trust claim" 1)
        AddAboutRows $flatRows (AboutCell "It records" "chain, signature, algorithm, hash, context" 1) (AboutCell "Not magic" "still needs rotation and key hygiene" 1)
        AddAboutRows $flatRows (AboutCell "It teaches" "trust behavior when primitives change" 1) (AboutCell "Not encrypt" "use OpenPGP flow for confidentiality" 1)
        AddAboutRows $flatRows (AboutCell "Operator" "local laboratory operator" 1) (AboutCell "Status" "private experiment, practical evidence" 1)
        AddAboutRows $flatRows (AboutCell "Twin" "OpenPGP Guard handles message secrecy" 1) (AboutCell "This guard" "handles certificate proof and file signatures" 1)
        AddAboutRows $flatRows (AboutCell "Guardrail" "public proof, private keys never shown" 1) (AboutCell "Rotation" "new root means new signer chain" 1)
        AddAboutRows $flatRows (AboutCell "Milestone" "chain, signature, hash, context in one view" 1) (AboutCell "Lab truth" "the evidence is in the logs" 1)

        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add((FrameTop "ABOUT / QUANTUM-SAFE DICTIONARY")) | Out-Null
        $lines.Add((FrameCenter "PQC CERTIFICATE GUARD  |  COMPANION TO OPENPGP QUANTUM GUARD")) | Out-Null
        $lines.Add((FrameCenter "PRIVATE X.509 TRUST ANCHOR  |  ML-DSA / SLH-DSA SIGNING  |  PUBLIC METADATA ONLY")) | Out-Null
        $lines.Add((FrameLine "")) | Out-Null

        $footerRows = 3
        $contentRows = [Math]::Max(8, $script:FrameRows - $lines.Count - $footerRows)
        $rowCount = [Math]::Min($contentRows, $flatRows.Count)
        for ($i=0; $i -lt $rowCount; $i++) { $lines.Add((DualFrameLine ([string]$flatRows[$i].L) ([string]$flatRows[$i].R))) | Out-Null }
        while ($lines.Count -lt ($script:FrameRows - $footerRows)) { $lines.Add((FrameLine "")) | Out-Null }

        $inner2 = $script:FrameWidth - 2
        $contentWidth = $inner2 - 6
        $gridText = Get-QuantumSignalText ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  SIGNAL  ") + (BrightGreen $gridText)))) | Out-Null
        $keysPlain = if ($flatRows.Count -gt $rowCount) { "ENTER/ESC back  N toggle NMS  |  condensed dictionary, more rows hidden by height" } else { "ENTER/ESC back  N toggle NMS  |  condensed two-column dictionary" }
        $keysPlain = ShortText $keysPlain ([Math]::Max(20, $contentWidth - 16))
        $lines.Add((FrameLine ((DimGreen "  KEYS    ") + (Pale $keysPlain)))) | Out-Null
        $lines.Add((FrameBottom "PQC TRUST DICTIONARY")) | Out-Null

        try { [Console]::SetCursorPosition(0,0) } catch { Clear-Host }
        Write-FrameLines @($lines)

        try {
            $deadline = (Get-Date).AddMilliseconds(140)
            while ((Get-Date) -lt $deadline -and -not [Console]::KeyAvailable) { Start-Sleep -Milliseconds 8 }
            if (-not [Console]::KeyAvailable) { if ($script:NmsEnabled) { $script:NmsTick++ }; continue }
            $key = [Console]::ReadKey($true)
        } catch {
            [void][Console]::ReadLine()
            $script:LastScreenKey = "Enter"
            return
        }

        switch ($key.Key) {
            "Enter" { $script:LastScreenKey = "Enter"; return }
            "Escape" { $script:LastScreenKey = "Escape"; return }
            "Q" { $script:LastScreenKey = "Q"; return }
            "N" { $script:NmsEnabled = -not $script:NmsEnabled; $script:Settings.NmsEnabled = $script:NmsEnabled; Save-Settings; $script:NmsTick += 4; Clear-PendingKeys }
        }
    }
}


function Settings-Menu {
    Clear-Host
    $null = Show-LinesScreen -Title "SETTINGS" -Content @(
        (KVLine "Workspace" (RedactPath ([string]$script:Settings.Workspace))),
        (KVLine "OpenSSL path" $(if ([string]::IsNullOrWhiteSpace([string]$script:Settings.OpenSslPath)) { "PATH lookup" } else { RedactPath ([string]$script:Settings.OpenSslPath) })),
        (KVLine "Algorithm" ([string]$script:Settings.Algorithm)),
        (KVLine "Lab name" ([string]$script:Settings.LabName)),
        (KVLine "Org name" ([string]$script:Settings.OrgName)),
        (KVLine "Context" ([string]$script:Settings.Context)),
        (KVLine "NMS" $(if ($script:NmsEnabled) { "ON" } else { "OFF" })),
        "",
        (DimGreen "  Press ENTER to edit settings, or ESC/Q to return.")) -Footer "ENTER edit settings"
    if ($script:LastScreenKey -ne "Enter") { $script:LastMessage = "Settings unchanged."; return }
    $ws = Read-Value "Workspace" ([string]$script:Settings.Workspace)
    $script:Settings.Workspace = $ws
    $script:Settings.OpenSslPath = Read-Value "OpenSSL executable path (blank uses PATH)" ([string]$script:Settings.OpenSslPath)
    $alg = Choose-Algorithm
    if ($null -eq $alg) { $script:LastMessage = "Settings edit cancelled."; return }
    if ($alg) { $script:Settings.Algorithm = $alg }
    $script:Settings.LabName = Read-Value "Lab name" ([string]$script:Settings.LabName)
    $script:Settings.OrgName = Read-Value "Organization name" ([string]$script:Settings.OrgName)
    $script:Settings.Context = Read-Value "Signature context" ([string]$script:Settings.Context)
    Save-Settings
    $script:LastMessage = "Settings saved."
}

# =============================================================================
# MAIN LOOP
# =============================================================================

Ensure-Workspace
$script:ExitRequested = $false
while (-not $script:ExitRequested) {
    try {
        $choice = Invoke-MainMenu
        switch ($choice) {
            "doctor"   { Setup-Doctor }
            "import"   { Import-ExistingLab }
            "root"     { Generate-RootCA }
            "signer"   { Generate-FileSigner }
            "sign"     { Sign-File }
            "verify"   { Verify-File }
            "inspect"  { Inspect-Certificates }
            "strength" { Show-Strength }
            "proof"    { Show-ProofCard }
            "about"    { Show-AboutPage }
            "settings" { Settings-Menu }
            "exit"     {
                Clear-Host
                Update-FrameSize
                $pad = Get-FrameLeftPad
                Write-Host ""
                Write-Host ($pad + (GradientText (CenterPlain "Quantum state sealed. PQC trust grid closed. Evidence remains verifiable." $script:FrameWidth) @(120,255,180) @(245,255,248)))
                Write-Host ""
                $script:ExitRequested = $true
                continue
            }
            default      { }
        }
    } catch {
        OperationFailed -Title "PQC Certificate Guard action failed" -Err $_
    }
}
try { [Console]::CursorVisible = $true } catch { }
