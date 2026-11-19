<#
.SYNOPSIS
    Fully disable, enable, or check IPv6 on Windows -- including the Teredo /
    6to4 / ISATAP tunnel interfaces that the adapter-properties checkbox leaves
    running.

.DESCRIPTION
    The IPv6 checkbox in adapter properties only unbinds native IPv6 from one
    NIC. It does NOT stop Windows' IPv6 tunnel pseudo-interfaces, which tunnel
    IPv6 over your IPv4 connection and can leak your real address around a
    SOCKS5/IPv4-only proxy. This script uses the DisabledComponents registry
    value (the system-wide switch) plus the tunnel-transition cmdlets so IPv6
    is genuinely off after a reboot.

    Run with no arguments to get an interactive menu (auto-detects current
    state first). Run with -Action for scripted / non-interactive use.

.PARAMETER Action
    Disable            - turn IPv6 fully off (registry 0xFF + tunnels disabled)
    DisableTunnelsOnly - proxy-leak fix without global IPv6 teardown
                         (registry 0x20 = prefer IPv4, tunnels disabled,
                         adapters left bound). Less disruptive than Disable;
                         Microsoft's recommended middle ground.
    Enable             - restore Windows default IPv6 behavior
    Status             - show current IPv6 state without changing anything

    Omit to launch the interactive menu.

.EXAMPLE
    .\Toggle-IPv6.ps1
    .\Toggle-IPv6.ps1 -Action Disable
    .\Toggle-IPv6.ps1 -Action DisableTunnelsOnly
    .\Toggle-IPv6.ps1 -Action Enable
    .\Toggle-IPv6.ps1 -Action Status

.NOTES
    Registry and tunnel changes require a REBOOT to fully take effect.
    Run from an elevated (Administrator) PowerShell prompt.

    'Enable' restores Windows DEFAULT IPv6 behavior (removes the registry
    override, sets tunnels to default, re-binds adapters). It is not a snapshot
    undo -- if you had a custom IPv6 configuration before running 'Disable',
    reapply that manually.

    Fully disabling IPv6 (Action=Disable) is a blunt instrument: Microsoft
    recommends against it because some components expect the IPv6 loopback
    (::1). For proxy-leak prevention you usually only need the tunnel
    interfaces off plus prefer-IPv4 (Action=DisableTunnelsOnly), not the
    global DisabledComponents=0xFF switch.

    Requires Windows 8 / Server 2012 or later (Get-NetTeredoConfiguration,
    Get-Net6to4Configuration, Get-NetIsatapConfiguration).
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Disable', 'DisableTunnelsOnly', 'Enable', 'Status')]
    [string]$Action
)

# ---- Self-elevate if not running as Administrator -------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "Not elevated -- relaunching as Administrator..." -ForegroundColor Yellow
    # -NoExit keeps the elevated window open so you can actually read the output
    # (the elevated process is separate and would otherwise close instantly).
    # -WorkingDirectory preserves the caller's CWD (elevated processes default
    # to system32). Arguments passed as an array avoid quoting fragility.
    $argList = @(
        '-NoExit'
        '-ExecutionPolicy', 'Bypass'
        '-File', $PSCommandPath
    )
    if ($Action) { $argList += @('-Action', $Action) }
    Start-Process -FilePath 'powershell.exe' `
        -ArgumentList $argList `
        -Verb RunAs `
        -WorkingDirectory (Get-Location).Path
    return
}

$regPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
$regName = 'DisabledComponents'

# Adapters that are pseudo/virtual tunnel or loopback interfaces. We skip these
# when mass-binding/unbinding ms_tcpip6 -- the tunnels are already handled via
# netsh, and touching the loopback pseudo-interface can upset ::1 on some builds.
$skipAdapterPattern = 'Teredo|ISATAP|6to4|Loopback|Pseudo'

function Invoke-Netsh {
    # Runs a netsh command, returns $true on success. On failure, emits the
    # (localized) output so the user can see why -- we no longer print a blind
    # [OK] when netsh silently errored.
    param([Parameter(Mandatory)][string]$Command)
    $out = & cmd.exe /c "$Command 2>&1"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [!] netsh failed ($LASTEXITCODE): $Command" -ForegroundColor Yellow
        $out | Where-Object { "$_".Trim() } | ForEach-Object {
            Write-Host "      $_" -ForegroundColor DarkYellow
        }
        return $false
    }
    return $true
}

function Get-RegistryState {
    # Returns the DWORD value, or $null if absent (including if the key itself
    # is missing). Avoids member-access on $null under StrictMode.
    $reg = Get-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
    if ($null -eq $reg) { return $null }
    return $reg.$regName
}

function Get-TunnelStateSummary {
    # Returns a hashtable of {Teredo, 6to4, ISATAP} -> state string. Uses typed
    # cmdlets so we don't parse localized netsh output.
    $result = @{}
    try { $result['Teredo'] = (Get-NetTeredoConfiguration -ErrorAction Stop).Type } catch { $result['Teredo'] = 'unknown' }
    try { $result['6to4']   = (Get-Net6to4Configuration   -ErrorAction Stop).State } catch { $result['6to4']   = 'unknown' }
    try { $result['ISATAP'] = (Get-NetIsatapConfiguration -ErrorAction Stop).State } catch { $result['ISATAP'] = 'unknown' }
    return $result
}

function Get-IPv6Verdict {
    # Condenses current state into a single headline verdict + color for the
    # menu / status header. Returns @{ State = '...'; Color = '...'; Detail = '...' }.
    $val   = Get-RegistryState
    $addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
             Where-Object { $_.IPAddress -notmatch '^(fe80|::1)' }
    $tun   = Get-TunnelStateSummary

    $tunnelsOff = ($tun['Teredo'] -match 'disabled') -and
                  ($tun['6to4']   -match 'disabled') -and
                  ($tun['ISATAP'] -match 'disabled')

    if ($val -eq 0xFF) {
        return @{ State = 'DISABLED (full)'; Color = 'Green'
                  Detail = 'DisabledComponents=0xFF; native IPv6 and tunnels off.' }
    }
    if ($val -eq 0x20) {
        return @{ State = 'PREFER IPv4 (tunnels off)'; Color = 'Green'
                  Detail = 'DisabledComponents=0x20; native IPv6 still bound.' }
    }
    if ($tunnelsOff -and -not $addrs) {
        return @{ State = 'TUNNELS OFF (native IPv6 bound)'; Color = 'Yellow'
                  Detail = 'Tunnel transition technologies disabled; no routable IPv6 present.' }
    }
    if ($addrs) {
        return @{ State = 'ENABLED (IPv6 addresses present)'; Color = 'Yellow'
                  Detail = 'Routable IPv6 is present -- a proxy leak is possible.' }
    }
    return @{ State = 'ENABLED (default)'; Color = 'Yellow'
              Detail = 'Windows default IPv6 behavior; no routable IPv6 currently assigned.' }
}

function Show-Status {
    # Rich-formatted status block. Reused by -Action Status and the menu.
    $verdict = Get-IPv6Verdict

    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  IPv6 STATUS" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Current state : " -NoNewline
    Write-Host $verdict.State -ForegroundColor $verdict.Color
    Write-Host "  $($verdict.Detail)" -ForegroundColor DarkGray
    Write-Host "------------------------------------------------" -ForegroundColor Cyan

    # Registry switch
    $val = Get-RegistryState
    if ($null -eq $val) {
        Write-Host "  DisabledComponents : (not set -- Windows default, IPv6 ON)"
    } else {
        Write-Host ("  DisabledComponents : 0x{0:X8}" -f $val)
    }

    # Any live IPv6 addresses -- this is the actual leak test, so show it first.
    Write-Host ""
    Write-Host "  --- Active IPv6 addresses (excluding fe80 / ::1) ---" -ForegroundColor Cyan
    $addrs = Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notmatch '^(fe80|::1)' }
    if ($addrs) {
        ($addrs | Format-Table InterfaceAlias, IPAddress, PrefixOrigin -AutoSize |
            Out-String) | Write-Host
        Write-Host "  IPv6 addresses are present -- a leak is still possible." -ForegroundColor Yellow
    } else {
        Write-Host "  None. No routable IPv6 present." -ForegroundColor Green
    }

    # Tunnel transition states -- typed cmdlets, localization-proof.
    Write-Host ""
    Write-Host "  --- Tunnel transition technologies ---" -ForegroundColor Cyan
    foreach ($t in 'Teredo', '6to4', 'ISATAP') {
        Write-Host "  [$t]" -ForegroundColor DarkCyan
        # -ErrorAction Stop is required: these cmdlets raise NON-terminating
        # errors (e.g. "Invalid class"), which try/catch would otherwise ignore,
        # dumping red error text and never reaching the netsh fallback.
        try {
            switch ($t) {
                'Teredo' { (Get-NetTeredoConfiguration -ErrorAction Stop | Select-Object Type, ServerName, State |
                              Format-List | Out-String).TrimEnd() | Write-Host }
                '6to4'   { (Get-Net6to4Configuration   -ErrorAction Stop | Select-Object State |
                              Format-List | Out-String).TrimEnd() | Write-Host }
                'ISATAP' { (Get-NetIsatapConfiguration -ErrorAction Stop | Select-Object State |
                              Format-List | Out-String).TrimEnd() | Write-Host }
            }
        } catch {
            Write-Host "  (typed cmdlet unavailable -- falling back to netsh)" -ForegroundColor DarkYellow
            $out = & cmd.exe /c "netsh interface $($t.ToLower()) show state 2>&1"
            if ($LASTEXITCODE -eq 0) {
                $out | Where-Object { $_ -and $_.Trim() } | ForEach-Object { Write-Host "  $_" }
            } else {
                Write-Host "  Not available on this system (netsh has no '$($t.ToLower())' context either)." -ForegroundColor DarkGray
                Write-Host "  The component isn't present, so it can't tunnel IPv6." -ForegroundColor DarkGray
            }
        }
    }
    Write-Host ""
}

function Set-AdapterBinding {
    # Shared loop for Disable/Enable. Skips pseudo/tunnel/loopback adapters
    # (see $skipAdapterPattern) so we don't fight the netsh layer above.
    param(
        [Parameter(Mandatory)][ValidateSet('Enable', 'Disable')][string]$Operation
    )
    $cmdlet = "${Operation}-NetAdapterBinding"
    foreach ($nic in (Get-NetAdapter -ErrorAction SilentlyContinue)) {
        if ($nic.InterfaceDescription -match $skipAdapterPattern -or
            $nic.Name -match $skipAdapterPattern) {
            Write-Host "  [-] skipped pseudo/tunnel adapter: $($nic.Name)" -ForegroundColor DarkGray
            continue
        }
        try {
            & $cmdlet -Name $nic.Name -ComponentID 'ms_tcpip6' -ErrorAction Stop | Out-Null
            $verb = if ($Operation -eq 'Disable') { 'unbound' } else { 're-bound' }
            Write-Host "  [OK] IPv6 $verb`: $($nic.Name)"
        } catch {
            Write-Host "  [!] $($nic.Name): $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

function Disable-IPv6Full {
    Write-Host "`nDisabling IPv6 system-wide..." -ForegroundColor Cyan

    # 1. Registry master switch: disable all IPv6 components, prefer IPv4.
    #    0xFF is Microsoft's documented "disable all + prefer IPv4" value.
    #    (Only the low bits are defined; 0xFFFFFFFF sets reserved bits and can
    #    cause odd behavior. The prefer-IPv4 bit 0x20 is already inside 0xFF.)
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name $regName -Value 0xFF `
        -PropertyType DWord -Force | Out-Null
    Write-Host "  [OK] DisabledComponents = 0xFF"

    # 2. Kill the tunnel transition technologies explicitly (effective now).
    $ok = $true
    $ok = (Invoke-Netsh 'netsh interface teredo set state disabled') -and $ok
    $ok = (Invoke-Netsh 'netsh interface 6to4 set state disabled')   -and $ok
    $ok = (Invoke-Netsh 'netsh interface isatap set state disabled') -and $ok
    if ($ok) { Write-Host "  [OK] Teredo / 6to4 / ISATAP disabled" }

    # 3. Unbind IPv6 from every real adapter for good measure.
    Set-AdapterBinding -Operation Disable

    Write-Host "`nDone. REBOOT for the registry change to fully apply." -ForegroundColor Green
}

function Disable-TunnelsOnly {
    # Middle-ground: prefer IPv4 (0x20) and kill tunnels, but leave native IPv6
    # bound on adapters and the loopback intact. This is the actual proxy-leak
    # fix without the blunt 0xFF teardown.
    Write-Host "`nDisabling IPv6 tunnel technologies (prefer IPv4)..." -ForegroundColor Cyan

    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    # 0x20 = "prefer IPv4 over IPv6" per MS docs. Leaves IPv6 itself enabled.
    New-ItemProperty -Path $regPath -Name $regName -Value 0x20 `
        -PropertyType DWord -Force | Out-Null
    Write-Host "  [OK] DisabledComponents = 0x20 (prefer IPv4)"

    $ok = $true
    $ok = (Invoke-Netsh 'netsh interface teredo set state disabled') -and $ok
    $ok = (Invoke-Netsh 'netsh interface 6to4 set state disabled')   -and $ok
    $ok = (Invoke-Netsh 'netsh interface isatap set state disabled') -and $ok
    if ($ok) { Write-Host "  [OK] Teredo / 6to4 / ISATAP disabled" }

    Write-Host "`nDone. REBOOT for the registry change to fully apply." -ForegroundColor Green
    Write-Host "Native IPv6 is still bound on adapters (not unbound)." -ForegroundColor DarkGray
}

function Enable-IPv6Full {
    Write-Host "`nRestoring default IPv6 behavior..." -ForegroundColor Cyan

    # 1. Remove the registry override (returns Windows to its default = enabled).
    if ($null -ne (Get-RegistryState)) {
        Remove-ItemProperty -Path $regPath -Name $regName -ErrorAction SilentlyContinue
        Write-Host "  [OK] DisabledComponents removed"
    } else {
        Write-Host "  [OK] DisabledComponents already absent"
    }

    # 2. Restore tunnel defaults.
    $ok = $true
    $ok = (Invoke-Netsh 'netsh interface teredo set state default') -and $ok
    $ok = (Invoke-Netsh 'netsh interface 6to4 set state default')   -and $ok
    $ok = (Invoke-Netsh 'netsh interface isatap set state default') -and $ok
    if ($ok) { Write-Host "  [OK] Teredo / 6to4 / ISATAP set to default" }

    # 3. Re-bind IPv6 on real adapters (skips pseudo/tunnel/loopback).
    Set-AdapterBinding -Operation Enable

    Write-Host "`nDone. REBOOT to fully restore IPv6." -ForegroundColor Green
}

function Show-Menu {
    # Interactive menu loop. Auto-detects state on entry and after each action.
    while ($true) {
        Show-Status

        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host "  MENU" -ForegroundColor Cyan
        Write-Host "================================================" -ForegroundColor Cyan
        Write-Host "  1) Enable IPv6 (restore Windows default)"
        Write-Host "  2) Disable IPv6 (full -- 0xFF, tunnels off, adapters unbound)"
        Write-Host "  3) Disable tunnels only (0x20, prefer IPv4 -- recommended for proxy use)"
        Write-Host "  4) Re-check current status"
        Write-Host "  5) Quit"
        Write-Host "------------------------------------------------" -ForegroundColor Cyan

        $choice = Read-Host "Select an option [1-5]"
        switch ($choice.Trim()) {
            '1' { Enable-IPv6Full;            Write-Host "`nPress Enter to re-check status..." -ForegroundColor DarkGray; [void](Read-Host) }
            '2' { Disable-IPv6Full;           Write-Host "`nPress Enter to re-check status..." -ForegroundColor DarkGray; [void](Read-Host) }
            '3' { Disable-TunnelsOnly;        Write-Host "`nPress Enter to re-check status..." -ForegroundColor DarkGray; [void](Read-Host) }
            '4' { }  # loop iteration prints status
            '5' { Write-Host "`nBye." -ForegroundColor Green; return }
            default {
                Write-Host "  Invalid choice -- enter 1-5." -ForegroundColor Red
                Start-Sleep -Milliseconds 800
            }
        }
    }
}

# ---- Entry point ----------------------------------------------------------
if (-not $Action) {
    # No args: interactive menu (auto-detects state first).
    Show-Menu
} else {
    switch ($Action) {
        'Disable'            { Disable-IPv6Full;      Show-Status }
        'DisableTunnelsOnly' { Disable-TunnelsOnly;   Show-Status }
        'Enable'             { Enable-IPv6Full;       Show-Status }
        'Status'             { Show-Status }
    }
}