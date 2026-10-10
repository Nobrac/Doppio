#requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Installs the Doppio credential provider: copies the binaries to Program
# Files and registers the provider and its filter.
#
# Part 1 does this with `reg import register.reg`. This script exists because
# a .reg import cannot look before it leaps - it overwrites whatever is at
# those keys and tells you nothing. The registration itself is still the .reg
# files; this only checks first and copies in the right order.
#
# Belongs in the Doppio repository root, next to build.bat.
# ---------------------------------------------------------------------------

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

# --- is somebody else already at our CLSID? --------------------------------
# register.reg carries the provider's CLSID. Read it out rather than hard-coding
# one, so this keeps working after new-guids.ps1 has been run.

$regText = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'register.reg') -Raw
$clsids = [regex]::Matches($regText, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}') |
          ForEach-Object { $_.Value } | Select-Object -Unique

if (-not $clsids) { throw "No CLSID found in register.reg. Is it the right file?" }

$cpRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
foreach ($clsid in $clsids) {
    $key = Join-Path $cpRoot $clsid
    if (Test-Path $key) {
        $owner = (Get-ItemProperty $key -ErrorAction SilentlyContinue).'(default)'
        if ($owner -and $owner -notlike '*AdminCafe*' -and $owner -notlike '*Doppio*') {
            throw "The credential provider CLSID $clsid is already registered to '$owner'. Run new-guids.ps1 to get your own CLSIDs rather than taking someone else's."
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
$out = & reg.exe import (Join-Path $PSScriptRoot 'register.reg') 2>&1
if ($LASTEXITCODE -ne 0) { throw "reg import register.reg failed: $out" }

$filterReg = Join-Path $PSScriptRoot 'register-filter.reg'
if (Test-Path -LiteralPath $filterReg) {
    $out = & reg.exe import $filterReg 2>&1
    if ($LASTEXITCODE -ne 0) { throw "reg import register-filter.reg failed: $out" }
    Write-Host "Registered the provider filter (hides the other sign-in options)."
}

Write-Host ""
Write-Host "Installed to $dest."
Write-Host "Reboot, then enroll an account before you deny anything else:"
Write-Host "    & '$dest\enroll.exe' <username>"
Write-Host ""
Write-Host "Keep a second administrator account that is NOT enrolled until you have"
Write-Host "seen the new tile work. A broken tile with no way back in is the one"
Write-Host "failure this cannot talk you out of."
