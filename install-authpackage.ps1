# Registers the Doppio LSA authentication package (SKELETON).
#
# This DLL is loaded INTO lsass.exe at boot, as SYSTEM. A broken one can leave
# the machine unbootable, past Safe Mode. Before you run this:
#
#   1. Take a VM snapshot. Not "recently" - now.
#   2. Have your BitLocker recovery key.
#   3. Know how to edit the registry offline from WinRE, so you can pull the
#      DLL back out of the package list if LSA refuses to start.
#
# This script APPENDS to "Authentication Packages". It never replaces the
# value: msv1_0 must stay in that list, or nobody on the machine can
# authenticate at all.
#
# Run from an elevated PowerShell.

$ErrorActionPreference = 'Stop'

$dll = 'TacAuthPackage'                       # base name, no extension
$src = Join-Path $PSScriptRoot "$dll.dll"
if (-not (Test-Path $src)) { throw "Build $dll.dll first (build.bat or build-lsa.bat)." }

# With LSA protection (RunAsPPL) on, lsass only loads plug-ins with a Microsoft
# LSA signature. This unsigned DLL would be skipped at boot - silently, from the
# point of view of whoever expects it to protect something. Refuse instead.
$lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$lsaProps = Get-ItemProperty -Path $lsaKey
if (($lsaProps.RunAsPPL -in 1, 2) -or ($lsaProps.RunAsPPLBoot -in 1, 2)) {
    throw "LSA protection (RunAsPPL) is on. lsass will not load the unsigned $dll.dll. Turn it off in the test VM first (and back on afterwards)."
}

$key  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$name = 'Authentication Packages'

# Read the current list first and refuse to touch anything that looks wrong.
$current = @((Get-ItemProperty -Path $key -Name $name).$name)
if ($current.Count -eq 0) {
    throw "'$name' is empty. That is not normal - refusing to write."
}
if ($current -notcontains 'msv1_0') {
    throw "'msv1_0' is not in '$name'. That is not normal - refusing to write."
}

Write-Host "Current '$name': $($current -join ', ')"

# LSA loads authentication packages from System32.
Copy-Item $src "$env:windir\System32\$dll.dll" -Force
Write-Host "Copied $dll.dll to System32."

if ($current -contains $dll) {
    Write-Host "'$dll' is already registered. Nothing to change."
} else {
    $new = $current + $dll
    Set-ItemProperty -Path $key -Name $name -Value $new -Type MultiString
    Write-Host "Registered '$dll'. '$name' is now: $($new -join ', ')"
}

Write-Host ''
Write-Host 'Reboot to load it.'
Write-Host 'Watch events (source "TheAdminCafe 2FA") or read the [Doppio-AP]'
Write-Host 'OutputDebugString lines under a kernel debugger.'
Write-Host ''
Write-Host 'If LSA will not start after the reboot: restore the snapshot, or boot'
Write-Host "WinRE and remove '$dll' from $key\$name offline."
Write-Host 'To remove normally: run uninstall-authpackage.ps1 and reboot.'
