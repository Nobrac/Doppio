# Removes the Doppio LSA authentication package. Run elevated, reboot after.
#
# Removing the registration is what stops LSA loading the DLL. Deleting the
# file alone is not enough, and deleting it while it is still registered is a
# good way to make LSA unhappy at the next boot. Registration first, reboot,
# then the file.

$ErrorActionPreference = 'Stop'

$dll  = 'TacAuthPackage'
$key  = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$name = 'Authentication Packages'

$current = @((Get-ItemProperty -Path $key -Name $name).$name)
$new     = @($current | Where-Object { $_ -ne $dll })

if ($new.Count -eq $current.Count) {
    Write-Host "'$dll' was not registered. Nothing to change."
} else {
    # Last line of defence: never leave the list without msv1_0.
    if ($new -notcontains 'msv1_0') {
        throw "Refusing to write: 'msv1_0' would be missing from '$name'."
    }
    Set-ItemProperty -Path $key -Name $name -Value $new -Type MultiString
    Write-Host "Removed '$dll'. '$name' is now: $($new -join ', ')"
}

Write-Host ''
Write-Host 'Reboot to unload it.'
Write-Host "After the reboot you can delete $env:windir\System32\$dll.dll."
