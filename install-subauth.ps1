# Registers the Doppio MSV1_0 sub-authentication FILTER (SKELETON).
#
# The filter is called by MSV1_0 AFTER it has validated a logon, and can only
# veto it. It runs INSIDE lsass.exe. A broken one can crash lsass - at boot or
# at the first network logon, because MSV1_0 loads a sub-authentication DLL
# the first time it needs it - and leave the machine unbootable, past Safe
# Mode. Take a VM snapshot first. Have your BitLocker recovery key and a way to
# edit the registry offline (WinRE) ready.
#
# The filter is registered as "Auth0". The numbered slots Auth1..AuthN are a
# different hook (Msv1_0SubAuthenticationRoutine) that has to do the whole
# password check itself - this project does not use them. See subauth_filter.h.
#
# Workstations and member servers only. On a domain controller Auth0 sees
# domain accounts, whose RIDs this project's local index knows nothing about.
#
# Run from an elevated PowerShell.

$ErrorActionPreference = 'Stop'
$dll = 'TacSubAuth'                          # base name, no extension
$src = Join-Path $PSScriptRoot "$dll.dll"
if (-not (Test-Path $src)) { throw "Build $dll.dll first (build.bat)." }

# DomainRole 4 = backup DC, 5 = primary DC.
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    throw "This is a domain controller. The filter's index only knows local accounts by RID; on a DC it would check domain RIDs against it. Refusing."
}

# With LSA protection (RunAsPPL) on, lsass only loads plug-ins with a Microsoft
# LSA signature. This unsigned DLL would be skipped - silently, from the point
# of view of whoever expects it to protect something. Refuse instead.
$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaProps = Get-ItemProperty -Path $lsaKey
if (($lsaProps.RunAsPPL -in 1, 2) -or ($lsaProps.RunAsPPLBoot -in 1, 2)) {
    throw "LSA protection (RunAsPPL) is on. lsass will not load the unsigned $dll.dll. Turn it off in the test VM first (and back on afterwards)."
}

# The registry is not the whole story. Windows 11 22H2 and later turns LSA
# protection on by default on new, enterprise-joined, HVCI-capable devices, and
# Microsoft does not document that this shows up in RunAsPPL. What it does
# document is the proof at runtime: WinInit event 12, "LSASS.exe was started
# as a protected process with level: 4", in the System log. Event ID 12 is
# used by other sources too, hence the provider check.
$boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$ppl  = Get-WinEvent -FilterHashtable @{ LogName = 'System'; Id = 12; StartTime = $boot } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -like '*Wininit*' } | Select-Object -First 1
if ($ppl) {
    throw "lsass runs as a protected process since the last boot (WinInit event 12). It will not load the unsigned $dll.dll. Turn LSA protection off in the test VM first (and back on afterwards)."
}

$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'
if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
$props = Get-ItemProperty -Path $key

# Auth0 holds exactly one DLL. Never overwrite someone else's filter.
if ($props.Auth0 -and $props.Auth0 -ne $dll) {
    throw "Auth0 is already used by '$($props.Auth0)'. Refusing to replace it."
}

# MSV1_0 loads sub-auth packages from the default DLL path (System32). If lsass
# has the DLL loaded (an older version is registered), this fails: uninstall,
# reboot, then retry.
try {
    Copy-Item $src "$env:windir\System32\$dll.dll" -Force
} catch {
    throw "Could not copy $dll.dll to System32 (in use by lsass?). Run uninstall-subauth.ps1, reboot, then install again."
}

# Older versions of this script registered the DLL under Auth1..Auth4 as a
# sub-authentication ROUTINE. That export no longer exists - remove the entry.
# (Those numbers are also in the range Microsoft reserves for itself, 1-127.)
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
Write-Host 'Reboot. MSV1_0 loads the filter the first time it needs it, so the first'
Write-Host 'network logon after the reboot is the moment of truth, not only the boot itself.'
Write-Host 'Refusals are logged (source "TheAdminCafe 2FA", event 210); every call writes a'
Write-Host '[Doppio-SubAuth] OutputDebugString line for the kernel debugger, including the'
Write-Host 'LogoffTime and KickoffTime MSV1_0 handed in.'
Write-Host 'To remove: run uninstall-subauth.ps1 and reboot.'
