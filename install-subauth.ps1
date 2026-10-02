# Registers the Doppio MSV1_0 sub-authentication package (SKELETON).
#
# A sub-auth package is called by MSV1_0 during its logon processing. It runs
# INSIDE lsass.exe. A broken one can leave the machine unbootable, past Safe
# Mode. Take a VM snapshot first. Have your BitLocker recovery key and a way to
# edit the registry offline (WinRE) ready.
#
# MSV1_0 calls the sub-auth package that a logon selects by its number. This
# script registers the DLL under the first free Auth# slot and prints that
# number. See the article chapter "2FA inside LSA" for what that does and does
# not cover.
#
# Run from an elevated PowerShell.

$ErrorActionPreference = 'Stop'
$dll = 'TacSubAuth'                          # base name, no extension
$src = Join-Path $PSScriptRoot "$dll.dll"
if (-not (Test-Path $src)) { throw "Build $dll.dll first (build.bat)." }

# MSV1_0 loads sub-auth packages from System32.
Copy-Item $src "$env:windir\System32\$dll.dll" -Force

$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }

# Is it already registered under some Auth# slot?
$props = Get-ItemProperty -Path $key
$existing = 1..4 | Where-Object { $props."Auth$_" -eq $dll } | Select-Object -First 1
if ($existing) {
    Write-Host "'$dll' already registered as sub-auth package Auth$existing."
    $slot = $existing
} else {
    # First free Auth1..Auth4 slot.
    $slot = 1..4 | Where-Object { -not $props."Auth$_" } | Select-Object -First 1
    if (-not $slot) { throw "No free Auth1..Auth4 slot under $key. Free one first." }
    New-ItemProperty -Path $key -Name "Auth$slot" -Value $dll -PropertyType String -Force | Out-Null
    Write-Host "Registered '$dll' as sub-auth package Auth$slot."
}

Write-Host ''
Write-Host "MSV1_0 will call it for logons that select sub-auth package $slot."
Write-Host 'Reboot to load it. Watch events (source "TheAdminCafe 2FA") or read the'
Write-Host '[Doppio-SubAuth] OutputDebugString lines under a kernel debugger.'
Write-Host 'To remove: run uninstall-subauth.ps1 and reboot.'
