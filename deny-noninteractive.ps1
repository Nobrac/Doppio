# Closes the non-interactive logon paths for a local account the SUPPORTED way:
# the "Deny log on ..." user rights. No code in lsass, nothing that can crash,
# and it survives reboots. On a real machine, this is the answer.
#
# Denied:   network (SMB, WinRM), batch (scheduled tasks), service.
# Allowed:  console logon, and RDP WITHOUT Network Level Authentication.
#
# RDP with NLA (the default) authenticates the user with a NETWORK logon
# before the session starts. Denying network logon therefore also blocks RDP
# with NLA for this account. You can:
#   - use the console only, or
#   - turn NLA off, so RDP goes straight to the logon screen with the 2FA tile
#     (more pre-authentication attack surface on the RDP port), or
#   - pass -KeepNetwork: RDP with NLA keeps working, but SMB/WinRM then still
#     accept the password alone for this account.
#
# NOT covered by any user right: runas, the UAC credential prompt and programs
# calling LogonUser interactively. Those are interactive logons that never show
# the logon screen, so they still need only the password.
#
# Usage (elevated):
#   .\deny-noninteractive.ps1 alice
#   .\deny-noninteractive.ps1 alice -KeepNetwork  # leave network logon alone
#   .\deny-noninteractive.ps1 alice -Remove       # undo
#
# Enroll the account in the 2FA tile BEFORE you deny its other paths, and keep
# a second admin account that still works. Otherwise a broken tile plus denied
# network logon means no way in.

param(
    [Parameter(Mandatory = $true)][string]$User,
    [switch]$Remove,
    [switch]$KeepNetwork
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

# On a domain member, a GPO that sets the same rights replaces this local
# setting at the next policy refresh, silently.
if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-Warning 'This computer is in a domain. A GPO that defines these user rights overwrites them at the next refresh. Set them in the GPO instead.'
}

# RemoteInteractive (SeDenyRemoteInteractiveLogonRight) is deliberately NOT in
# this list. RDP shows the tile, so it keeps its second factor.
$rights = @(
    'SeDenyNetworkLogonRight',      # 3  - SMB, WinRM, and the NLA step of RDP
    'SeDenyBatchLogonRight',        # 4  - scheduled tasks
    'SeDenyServiceLogonRight'       # 5  - service logons
)
# -Remove always cleans up all three, whatever was used when adding.
if ($KeepNetwork -and -not $Remove) {
    $rights = @($rights | Where-Object { $_ -ne 'SeDenyNetworkLogonRight' })
}

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
    if ($KeepNetwork) {
        Write-Host "Denied batch and service logon for $User. Network logon (SMB, WinRM) still"
        Write-Host 'accepts the password alone. RDP with NLA keeps working and shows the 2FA tile.'
    } else {
        Write-Host "Denied network, batch and service logon for $User."
        Write-Host 'The console still works and asks for the code. RDP works only with NLA'
        Write-Host 'turned off, because NLA itself is a network logon.'
    }
    Write-Host 'runas and the UAC credential prompt are NOT covered and still take the password alone.'
}
Write-Host 'Takes effect at the next logon attempt - no reboot needed.'
Write-Host "Check it with:  secedit /export /areas USER_RIGHTS /cfg con"
