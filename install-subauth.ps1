# Registers the Doppio MSV1_0 sub-authentication FILTER (SKELETON).
#
# The filter is called by MSV1_0 AFTER it has validated a logon, and can only
# veto it. It runs INSIDE lsass.exe. A broken one can leave the machine
# unbootable, past Safe Mode. Take a VM snapshot first. Have your BitLocker
# recovery key and a way to edit the registry offline (WinRE) ready.
#
# The filter is registered as "Auth0". The numbered slots Auth1..AuthN are a
# different hook (Msv1_0SubAuthenticationRoutine) that has to do the whole
# password check itself - this project does not use them. See subauth.h.
#
# Run from an elevated PowerShell.

$ErrorActionPreference = 'Stop'
$dll = 'TacSubAuth'                          # base name, no extension
$src = Join-Path $PSScriptRoot "$dll.dll"
if (-not (Test-Path $src)) { throw "Build $dll.dll first (build.bat)." }

$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
$props = Get-ItemProperty -Path $key

# Auth0 holds exactly one DLL. Never overwrite someone else's filter.
if ($props.Auth0 -and $props.Auth0 -ne $dll) {
    throw "Auth0 is already used by '$($props.Auth0)'. Refusing to replace it."
}

# MSV1_0 loads sub-auth packages from System32. If lsass has the DLL loaded
# (an older version is registered), this fails: uninstall, reboot, then retry.
try {
    Copy-Item $src "$env:windir\System32\$dll.dll" -Force
} catch {
    throw "Could not copy $dll.dll to System32 (in use by lsass?). Run uninstall-subauth.ps1, reboot, then install again."
}

# Older versions of this script registered the DLL under Auth1..Auth4 as a
# sub-authentication ROUTINE. That export no longer exists - remove the entry.
1..4 | ForEach-Object {
    if ($props."Auth$_" -eq $dll) {
        Remove-ItemProperty -Path $key -Name "Auth$_"
        Write-Host "Removed the old registration Auth$_."
    }
}

if ($props.Auth0 -eq $dll) {
    Write-Host "'$dll' is already registered as Auth0."
} else {
    New-ItemProperty -Path $key -Name 'Auth0' -Value $dll -PropertyType String -Force | Out-Null
    Write-Host "Registered '$dll' as Auth0 (sub-authentication filter)."
}

Write-Host ''
Write-Host 'Index existing enrollments by RID, which the filter reads:'
Write-Host '  & "C:\Program Files\TheAdminCafe\enroll.exe" /reindex'
Write-Host ''
Write-Host 'Reboot to load it. Refusals are logged (source "TheAdminCafe 2FA", event 210);'
Write-Host 'every call writes a [Doppio-SubAuth] OutputDebugString line for the kernel debugger.'
Write-Host 'If LSA protection (RunAsPPL) is on, lsass will not load this unsigned DLL at all.'
Write-Host 'To remove: run uninstall-subauth.ps1 and reboot.'
