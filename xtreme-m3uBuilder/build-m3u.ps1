<#
    Build-M3U.ps1  —  build your playlist from player_api.php (which works),
    bypassing the get.php endpoint that Cloudflare is blocking.

    It calls three actions on player_api.php:
      - (auth check)            confirm the account
      - get_live_categories     map category_id -> group name
      - get_live_streams        every live channel
    ...then writes a standard #EXTM3U file locally. No get.php, no Cloudflare fight.

    Usage:
      powershell -ExecutionPolicy Bypass -File .\Build-M3U.ps1
        -> prompts for details
    Or:
      .\Build-M3U.ps1 -M3uUrl "http://host:port/get.php?username=U&password=P"
      .\Build-M3U.ps1 -Server "http://host:port" -Username "U" -Password "P"

    Options:
      -Ext ts|m3u8   stream URL extension (default ts; your account allows both)
      -OutFile name  output filename (default playlist.m3u)
#>

[CmdletBinding()]
param(
    [string]$M3uUrl,
    [string]$Server,
    [string]$Username,
    [string]$Password,
    [string]$UserAgent = "VLC/3.0.20 LibVLC/3.0.20",
    [string]$OutFile   = "playlist.m3u",
    [ValidateSet("ts","m3u8")]
    [string]$Ext       = "ts"
)

# ------------------------- inputs -------------------------
if (-not $M3uUrl -and -not $Server) {
    Write-Host "`nBuild M3U from the working API" -ForegroundColor Cyan
    Write-Host "  [1] Paste the whole M3U URL"
    Write-Host "  [2] Enter server / username / password separately"
    if ((Read-Host "Choice (1 or 2)") -eq '1') {
        $M3uUrl = Read-Host "Paste your full M3U URL"
    } else {
        $Server   = Read-Host "Server address (e.g. http://host.com:8080)"
        $Username = Read-Host "Username"
        $Password = Read-Host "Password"
    }
}

if ($M3uUrl) {
    try {
        $uri  = [System.Uri]$M3uUrl
        $Server = "{0}://{1}" -f $uri.Scheme, $uri.Host
        if (-not $uri.IsDefaultPort) { $Server = "$Server`:$($uri.Port)" }
        foreach ($pair in ($uri.Query.TrimStart('?') -split '&')) {
            if ($pair -match '=') {
                $k, $v = $pair -split '=', 2
                if ($k -eq 'username') { $Username = [System.Uri]::UnescapeDataString($v) }
                if ($k -eq 'password') { $Password = [System.Uri]::UnescapeDataString($v) }
            }
        }
    } catch {
        Write-Host "ERROR: couldn't parse that URL." -ForegroundColor Red; exit 1
    }
}

if ($Server -notmatch '^[a-zA-Z]+://') { $Server = "http://$Server" }
$Server = $Server.TrimEnd('/')
if (-not $Username -or -not $Password) {
    Write-Host "ERROR: missing username or password." -ForegroundColor Red; exit 1
}

$apiBase = "$Server/player_api.php?username=$Username&password=$Password"

# small helper: call an API action the SAME way Check-IPTV did (that call is known
# to work on your machine), then parse the JSON ourselves. Using Invoke-WebRequest
# + -UseBasicParsing avoids the Windows PowerShell 5.1 Invoke-RestMethod quirk that
# throws "The URI prefix is not recognized".
function Invoke-Api {
    param([string]$Action)
    $u = if ($Action) { "$apiBase&action=$Action" } else { $apiBase }
    $resp = Invoke-WebRequest -Uri $u -UserAgent $UserAgent -MaximumRedirection 5 `
                -TimeoutSec 120 -UseBasicParsing -ErrorAction Stop
    return ($resp.Content | ConvertFrom-Json)
}

# ------------------------- step 1: auth -------------------------
Write-Host "`nStep 1: confirming account ..." -ForegroundColor Cyan
$maskedBase = $apiBase -replace '(password=)[^&]*', '${1}***'
Write-Host "  calling: $maskedBase" -ForegroundColor DarkGray
try {
    $info = Invoke-Api $null
} catch {
    Write-Host "  API call failed: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
if (-not $info.user_info -or $info.user_info.auth -ne 1) {
    Write-Host "  Auth failed - check credentials." -ForegroundColor Red; exit 1
}
Write-Host "  OK - status '$($info.user_info.status)'" -ForegroundColor Green

# ------------------------- step 2: categories -------------------------
Write-Host "Step 2: fetching live categories ..." -ForegroundColor Cyan
try {
    $cats = Invoke-Api "get_live_categories"
} catch {
    Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
$catMap = @{}
foreach ($c in $cats) { $catMap["$($c.category_id)"] = $c.category_name }
Write-Host "  $($catMap.Count) categories" -ForegroundColor Green

# ------------------------- step 3: streams -------------------------
Write-Host "Step 3: fetching live streams ..." -ForegroundColor Cyan
try {
    $streams = Invoke-Api "get_live_streams"
} catch {
    Write-Host "  Failed: $($_.Exception.Message)" -ForegroundColor Red; exit 1
}
if (-not $streams -or $streams.Count -eq 0) {
    Write-Host "  API returned no streams." -ForegroundColor Yellow; exit 1
}
Write-Host "  $($streams.Count) streams" -ForegroundColor Green

# ------------------------- step 4: build -------------------------
Write-Host "Step 4: writing playlist ..." -ForegroundColor Cyan
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("#EXTM3U")
foreach ($s in $streams) {
    $sid  = $s.stream_id
    $name = ("$($s.name)") -replace '"', ''          # strip quotes so attributes can't break
    $logo = "$($s.stream_icon)"
    $epg  = "$($s.epg_channel_id)"
    $grp  = $catMap["$($s.category_id)"]
    if ([string]::IsNullOrWhiteSpace($grp)) { $grp = "Uncategorized" }

    $extinf = "#EXTINF:-1 tvg-id=`"$epg`" tvg-name=`"$name`" tvg-logo=`"$logo`" group-title=`"$grp`",$name"
    $url    = "$Server/live/$Username/$Password/$sid.$Ext"
    $lines.Add($extinf)
    $lines.Add($url)
}

$path = Join-Path (Get-Location) $OutFile
[System.IO.File]::WriteAllLines($path, $lines)

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  Wrote $($streams.Count) channels to $path" -ForegroundColor Green
Write-Host "  Groups: $($catMap.Count)" -ForegroundColor Green
Write-Host "`nFirst lines:" -ForegroundColor Green
($lines | Select-Object -First 5) | ForEach-Object { "  $_" }

# quick group breakdown so you can SEE what you got
Write-Host "`nChannels per group (top 15):" -ForegroundColor Cyan
$streams | Group-Object { $catMap["$($_.category_id)"] } |
    Sort-Object Count -Descending | Select-Object -First 15 |
    ForEach-Object { "  {0,5}  {1}" -f $_.Count, $_.Name }
