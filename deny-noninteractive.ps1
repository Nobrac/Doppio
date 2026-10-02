# Closes the non-interactive logon paths for a local account the SUPPORTED way:
# the "Deny log on ..." user rights. No code in lsass, nothing that can crash,
# and it survives reboots. On a real machine, this is the answer.
#
# Denied:   network (SMB), batch (scheduled tasks), service.
# Allowed:  console logon and RDP - both show the 2FA tile from Part 1, so a
#           second factor is actually possible there.
#
# Usage (elevated):
#   .\deny-noninteractive.ps1 alice
#   .\deny-noninteractive.ps1 alice -Remove      # undo
#
# Enroll the account in the 2FA tile BEFORE you deny its other paths, and keep
# a second admin account that still works. Otherwise a broken tile plus denied
# network logon means no way in.

param(
    [Parameter(Mandatory = $true)][string]$User,
    [switch]$Remove
)

$ErrorActionPreference = 'Stop'

# secedit works on SIDs, not names. Resolve against this computer's SAM.
try {
    $account = New-Object System.Security.Principal.NTAccount($env:COMPUTERNAME, $User)
    $sid     = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value
} catch {
    throw "Could not resolve local account '$User' on $env:COMPUTERNAME."
}
Write-Host "$env:COMPUTERNAME\$User -> $sid"

# RemoteInteractive (SeDenyRemoteInteractiveLogonRight) is deliberately NOT in
# this list. RDP shows the tile, so it keeps its second factor.
$rights = @(
    'SeDenyNetworkLogonRight',      # 3  - SMB and most remote access
    'SeDenyBatchLogonRight',        # 4  - scheduled tasks
    'SeDenyServiceLogonRight'       # 5  - service logons
)

$work = Join-Path $env:TEMP 'tac-secpol'
New-Item -ItemType Directory -Force $work | Out-Null
$exported = Join-Path $work 'exported.inf'
$apply    = Join-Path $work 'apply.inf'
$database = Join-Path $work 'tac.sdb'
Remove-Item $exported, $apply, $database -ErrorAction SilentlyContinue

# 1. Export what the machine has now. We must preserve the existing members of
#    each right: secedit /configure REPLACES a right's member list wholesale,
#    so writing only our SID would strip everyone else off it.
& secedit /export /areas USER_RIGHTS /cfg $exported | Out-Null
if (-not (Test-Path $exported)) { throw 'secedit /export failed.' }

$lines = Get-Content -Path $exported -Encoding Unicode

function Get-Members([string[]]$infLines, [string]$right) {
    $line = $infLines | Where-Object { $_ -match "^\s*$right\s*=" } | Select-Object -First 1
    if (-not $line) { return @() }
    $value = ($line -split '=', 2)[1].Trim()
    if (-not $value) { return @() }
    return @($value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

# 2. Merge our SID in (or out) of each right, leaving everyone else alone.
$entry   = "*$sid"                     # secedit prefixes SIDs with '*'
$section = [System.Collections.Generic.List[string]]::new()
$changed = $false

foreach ($right in $rights) {
    $members = Get-Members $lines $right
    $has     = $members -contains $entry

    if ($Remove) {
        if (-not $has) { Write-Host "  $right : not set, skipping"; continue }
        $members = @($members | Where-Object { $_ -ne $entry })
        Write-Host "  $right : removing $User"
    } else {
        if ($has) { Write-Host "  $right : already set, skipping"; continue }
        $members = @($members) + $entry
        Write-Host "  $right : adding $User"
    }

    $changed = $true
    $section.Add("$right = $($members -join ',')")
}

if (-not $changed) {
    Write-Host ''
    Write-Host 'Nothing to change.'
    return
}

# 3. Write a minimal INF with only the rights we touched, as UTF-16 (secedit
#    will not read anything else), and apply it.
$inf = @(
    '[Unicode]'
    'Unicode=yes'
    '[Version]'
    'signature="$CHICAGO$"'
    'Revision=1'
    '[Privilege Rights]'
) + $section

[System.IO.File]::WriteAllLines($apply, $inf, [System.Text.Encoding]::Unicode)

& secedit /configure /db $database /cfg $apply /areas USER_RIGHTS | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "secedit /configure failed (exit $LASTEXITCODE). See $env:windir\security\logs\scesrv.log."
}

Write-Host ''
if ($Remove) {
    Write-Host "Removed the deny rights for $User. Network, batch and service logon work again."
} else {
    Write-Host "Denied network, batch and service logon for $User."
    Write-Host 'Console and RDP still work and still ask for the TOTP code.'
}
Write-Host 'Takes effect at the next logon attempt - no reboot needed.'
Write-Host "Check it with:  secedit /export /areas USER_RIGHTS /cfg con"
