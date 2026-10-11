#requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs the Doppio credential provider: copies the binaries to Program
    Files and registers the provider. The filter that hides every other
    sign-in option is a separate, deliberate second step.

.DESCRIPTION
    Step 1 (default): copy and register the provider. Nothing else changes on
    the logon screen - the 2FA tile shows up under "Sign-in options", next to
    the usual ones.

    Then enroll every account that signs in at the console or over RDP,
    including your break-glass admin, and test each one with the 2FA tile.

    Step 2 (-EnableFilter): hide every other sign-in option. Refuses while an
    enabled local account is not enrolled, because that account could not sign
    in at all afterwards: its 2FA tile has no secret to check, and the tiles it
    used before are gone.

.PARAMETER EnableFilter
    Register the filter (register-filter.reg) after checking that every enabled
    local account is enrolled.

.PARAMETER AllowUnenrolled
    Local account names that may stay unenrolled with the filter on, because
    they never sign in at the console or over RDP (service accounts, for
    example). Each one is named explicitly; there is no switch to skip the check.

.EXAMPLE
    .\install-doppio.ps1
    & 'C:\Program Files\TheAdminCafe\enroll.exe' alice
    & 'C:\Program Files\TheAdminCafe\enroll.exe' breakglass
    # sign out, test both accounts with the 2FA tile, then:
    .\install-doppio.ps1 -EnableFilter
#>
param(
    [switch]$EnableFilter,
    [string[]]$AllowUnenrolled = @()
)

$ErrorActionPreference = 'Stop'

# Belongs in the Doppio repository root, next to build.bat. Part 1 does the
# same with `reg import register.reg`; this script exists because a .reg import
# cannot look before it leaps - it overwrites whatever is at those keys and
# tells you nothing. The registration itself is still the .reg files; this only
# checks first and copies in the right order.

$dest = 'C:\Program Files\TheAdminCafe'

# --- what has to be in the source folder -----------------------------------

$required = @('TacProvider.dll', 'enroll.exe', 'register.reg')
$missing = $required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $PSScriptRoot $_)) }
if ($missing) {
    throw "Missing build output: $($missing -join ', '). Run build.bat from the x64 Native Tools Command Prompt first."
}

# Optional: the LSA pieces, only if they were built. The filter and the
# authentication package are registered by their own scripts, not here - this
# only puts them where those scripts expect to find them.
$optional = @('TacSubAuth.dll', 'TacAuthPackage.dll', 'register-filter.reg',
              'unregister.reg', 'deny-noninteractive.ps1')

$regFile    = Join-Path $PSScriptRoot 'register.reg'
$filterReg  = Join-Path $PSScriptRoot 'register-filter.reg'
$guidRegex  = '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}'

# --- step 2: the filter -----------------------------------------------------

if ($EnableFilter) {
    if (-not (Test-Path -LiteralPath $filterReg)) {
        throw "register-filter.reg is missing next to this script."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $dest 'TacProvider.dll'))) {
        throw "Doppio is not installed in $dest yet. Run this script without -EnableFilter first."
    }

    # Every stored secret is a REG_BINARY value named by the account's SID.
    $store = 'HKLM:\SOFTWARE\TheAdminCafe\2FA'
    $enrolled = @()
    if (Test-Path $store) {
        $item = Get-Item -Path $store
        $enrolled = @($item.Property | Where-Object {
            $_ -like 'S-1-*' -and $item.GetValueKind($_) -eq [Microsoft.Win32.RegistryValueKind]::Binary
        })
    }
    if ($enrolled.Count -eq 0) {
        throw "No account is enrolled. Enroll every account that signs in at the console or over RDP first: & '$dest\enroll.exe' <username>"
    }

    $allowed = @($AllowUnenrolled | ForEach-Object { $_.ToLowerInvariant() })
    $locked  = @(Get-LocalUser | Where-Object {
        $_.Enabled -and
        ($enrolled -notcontains $_.SID.Value) -and
        ($allowed -notcontains $_.Name.ToLowerInvariant())
    })
    if ($locked.Count -gt 0) {
        $names = ($locked | ForEach-Object { $_.Name }) -join ', '
        throw ("These enabled local accounts are not enrolled and could not sign in at the console or over RDP " +
               "once the filter is on: $names. Enroll them, disable them, or - only for accounts that never sign " +
               "in interactively - name them with -AllowUnenrolled.")
    }

    # Same look-before-you-leap as for the provider: never take a filter key
    # that someone else's filter already holds.
    $filterRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters'
    $filterText = Get-Content -LiteralPath $filterReg -Raw
    foreach ($clsid in ([regex]::Matches($filterText, $guidRegex) | ForEach-Object { $_.Value } | Select-Object -Unique)) {
        $key = Join-Path $filterRoot $clsid
        if (Test-Path $key) {
            $owner = (Get-ItemProperty $key -ErrorAction SilentlyContinue).'(default)'
            if ($owner -and $owner -notlike '*AdminCafe*' -and $owner -notlike '*Doppio*') {
                throw "The filter CLSID $clsid is already registered to '$owner'. Run new-guids.ps1 to get your own CLSIDs."
            }
        }
    }

    $out = & reg.exe import $filterReg 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg import register-filter.reg failed: $out" }

    Write-Host "Registered the filter. The logon and unlock screens now show only the 2FA tiles."
    Write-Host ''
    Write-Host 'Before you sign out: know your way back. If no tile works, boot WinRE, load the'
    Write-Host 'SOFTWARE hive offline and delete the filter key (see README). Practise it once.'
    return
}

# --- step 1: is somebody else already at our CLSIDs? ------------------------
# register.reg carries the provider's and the filter's CLSIDs (the filter is
# COM-registered here too, only not activated). Read them out rather than
# hard-coding them, so this keeps working after new-guids.ps1 has been run, and
# check every place the import would write to.

$regText = Get-Content -LiteralPath $regFile -Raw
$clsids = [regex]::Matches($regText, $guidRegex) | ForEach-Object { $_.Value } | Select-Object -Unique
if (-not $clsids) { throw "No CLSID found in register.reg. Is it the right file?" }

$places = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers',
    'HKLM:\SOFTWARE\Classes\CLSID'
)
foreach ($clsid in $clsids) {
    foreach ($root in $places) {
        $key = Join-Path $root $clsid
        if (Test-Path $key) {
            $owner = (Get-ItemProperty $key -ErrorAction SilentlyContinue).'(default)'
            if ($owner -and $owner -notlike '*AdminCafe*' -and $owner -notlike '*Doppio*') {
                throw "CLSID $clsid is already registered to '$owner' under $root. Run new-guids.ps1 to get your own CLSIDs rather than taking someone else's."
            }
        }
    }
}

# --- copy, then register ---------------------------------------------------
# Order matters for the same reason it does in the Ristretto installer: the
# registry must never name a DLL that is not on disk yet. A reboot in between
# would leave LogonUI looking for a provider that is not there.

New-Item -ItemType Directory -Force -Path $dest | Out-Null

foreach ($f in $required + $optional) {
    $src = Join-Path $PSScriptRoot $f
    if (Test-Path -LiteralPath $src) {
        Copy-Item -LiteralPath $src -Destination (Join-Path $dest $f) -Force
        Write-Host "  copied $f"
    }
}

# The tile reads the secret from the store, and the store's own ACL protects
# it. The install folder itself just needs to not be writable by a normal
# user - which Program Files already is - so nothing is changed here.

Write-Host ""
Write-Host "Registering the credential provider..."
$out = & reg.exe import $regFile 2>&1
if ($LASTEXITCODE -ne 0) { throw "reg import register.reg failed: $out" }

Write-Host ""
Write-Host "Installed to $dest. The other sign-in options stay visible for now."
Write-Host ""
Write-Host "Next:"
Write-Host "  1. Enroll every account that signs in at the console or over RDP -"
Write-Host "     your break-glass admin too:"
Write-Host "         & '$dest\enroll.exe' <username>"
Write-Host "  2. Sign out and sign in once with each of them through the 2FA tile"
Write-Host "     (Sign-in options, the brown 2FA icon)."
Write-Host "  3. Only then hide the other sign-in options:"
Write-Host "         .\install-doppio.ps1 -EnableFilter"
Write-Host ""
Write-Host "An account that is not enrolled cannot sign in at the console once the filter"
Write-Host "is on. Step 3 checks that for you; 'enroll.exe /list' shows who is enrolled."
