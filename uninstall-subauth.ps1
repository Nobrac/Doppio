# Removes the Doppio MSV1_0 sub-authentication package. Run elevated, reboot after.
$ErrorActionPreference = 'Stop'
$dll = 'TacSubAuth'
$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'

$props = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
$removed = $false
if ($props) {
    1..4 | ForEach-Object {
        if ($props."Auth$_" -eq $dll) {
            Remove-ItemProperty -Path $key -Name "Auth$_"
            Write-Host "Removed sub-auth registration Auth$_."
            $removed = $true
        }
    }
}
if (-not $removed) { Write-Host "'$dll' was not registered as a sub-auth package." }
Write-Host "Reboot to unload it. You can delete $env:windir\System32\$dll.dll afterwards."
