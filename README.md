# Doppio ☕☕

A TOTP second factor for local Windows accounts, built as a Credential
Provider. You log on with password and a 6-digit code from any authenticator
app, at logon and unlock, locally and over RDP.

> Learning demo, not a product. Use it only in a throwaway VM with a snapshot.
> A broken credential provider can lock you out of the machine, and the LSA
> pieces below can leave it unbootable.

## Build

From the "x64 Native Tools Command Prompt" of Visual Studio:

```bat
build.bat
```

This builds `TacProvider.dll`, `enroll.exe` and the two LSA skeletons
`TacAuthPackage.dll` and `TacSubAuth.dll`. Run `new-guids.ps1` once before you
use it anywhere, so you don't use the CLSIDs of this repository.

## Install the credential provider

In an elevated PowerShell on the test VM:

```powershell
.\install-doppio.ps1

# Enroll every local account that signs in at the console or over RDP,
# including a break-glass admin
& "C:\Program Files\TheAdminCafe\enroll.exe" alice
& "C:\Program Files\TheAdminCafe\enroll.exe" breakglass
```

`install-doppio.ps1` copies the files to `C:\Program Files\TheAdminCafe` and
imports `register.reg`, after checking that no other provider already holds
those CLSIDs. (By hand: create the folder, copy `TacProvider.dll` and
`enroll.exe`, `reg import .\register.reg`.) `enroll.exe` shows the secret and asks for a code before it
stores anything, so a secret mistyped into the app can't lock you out. Log off,
click "Sign-in options", choose the brown 2FA icon and log on with password and
code.

Once this works for every account, hide all other sign-in options:

```powershell
.\install-doppio.ps1 -EnableFilter
```

The script refuses while an enabled local account is not enrolled, since that
account could no longer sign in. Name accounts that never sign in
interactively with `-AllowUnenrolled svc-backup`. (By hand:
`reg import .\register-filter.reg`, without that check.)

After that, logon and unlock show only the 2FA tiles: no password tile, PIN or
Windows Hello, otherwise the code would be optional. Microsoft advises against
this because a broken provider leaves no way in. Recovery options:

- The 2FA provider always shows an "Other user" tile, so a hidden break-glass
  admin can still sign in.
- While no account is enrolled, the filter hides nothing, so importing it too
  early or after `enroll.exe /purge` cannot lock you out. A secret left over
  from an account deleted without `/remove` still counts; `enroll.exe /list`
  shows it as "(deleted account)" and `enroll.exe /remove <SID>` removes it.
- If `TacProvider.dll` cannot be loaded, Windows shows all sign-in options
  again. Confirm this once in the VM by renaming the DLL.
- Otherwise boot WinRE, load the SOFTWARE hive offline and delete
  `Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B1E7C9A0-2F4D-4C6B-9A11-0000C0FFEE02}`
  (your GUID after `new-guids.ps1`). Practise this before you need it.

The tile checks the password first (with `LogonUser`) and looks at the code
only when the password was right. Windows counts wrong passwords, so set an
account lockout policy as usual; the tile counts wrong codes. Nobody can lock
an account with random codes without its password. Each sign-in leaves one
extra logon event (4624, type 2, LogonUI.exe) in the Security log.

## Managing enrollments

- `enroll.exe /unlock alice` unlocks a user after too many wrong codes.
- `enroll.exe /list` shows who is enrolled and whether the LSA indexes know them.
- `enroll.exe /remove alice` drops the secret, state and index entries. Run it
  before you delete the Windows account; afterwards use the SID from `/list`:
  `enroll.exe /remove S-1-5-21-...`.
- `enroll.exe /reindex` after renaming an enrolled account or updating from a
  version without the RID index.

Every `enroll.exe` run except `/list` and `/purge` re-applies the
SYSTEM-and-Administrators ACL to the store keys.

Uninstall: `enroll.exe /purge` (deletes all secrets, state and indexes), then
`reg import .\unregister.reg`, reboot and delete the folder (it also holds
`state.lock`). Without `/purge` the secrets stay in the registry and come back
on a reinstall.

Events go to the Application log, source "TheAdminCafe 2FA": 100 password and
code accepted, 101 wrong code, 102 code already used, 103/104 lock, 105 not
enrolled, 106 state error, 107 password refused, 108 final result from LSA.
From the LSA pieces: 200 authentication package loaded (written before the
Eventlog service runs, so usually only visible in the debugger), 201/202
package denied/declined a logon, 210 filter refused a logon.

## What the tile does not cover

The credential provider only sees the logon and unlock screens. These still
take the password alone:

- `runas`, the UAC credential prompt and any program calling `LogonUser`
  interactively. No user right separates them from console logon, and the
  filter below does not see them.
- Safe Mode and offline access. Use BitLocker (TPM + PIN) and a UEFI password.
- Network logon (SMB, WinRM), scheduled tasks and services. The next section
  covers these.

## Closing the non-interactive paths

### 1. User rights (use this on real machines)

Deny network, batch and service logon for an enrolled account. Console logon
with the 2FA tile still works:

```powershell
.\deny-noninteractive.ps1 alice
```

RDP with Network Level Authentication (the default) checks the password with a
network logon first, so this also blocks NLA for that account. Use the console,
turn NLA off (RDP then goes straight to the 2FA tile, with more attack surface
on the RDP port), or run the script with `-KeepNetwork` and accept that
SMB/WinRM still take the password alone. On a domain member, a GPO that defines
these rights overwrites them.

### 2. LSA authentication package (`ap.cpp`, `TacAuthPackage.dll`)

Runs in `lsass.exe` to show the package interface. It is not a security
control. A logon only reaches it if the caller selects it by package id, and
every such logon fails because it never builds a token: an enrolled account on
a non-interactive path gets `STATUS_ACCOUNT_RESTRICTION`, everything else
`STATUS_INVALID_LOGON_TYPE`. It reads only the user name from the logon buffer,
never the password, and checks enrollment with one registry read (no DPAPI, no
name/SID lookup).

### 3. MSV1_0 sub-authentication filter (`subauth.cpp`, `TacSubAuth.dll`)

Registered as `Auth0`. MSV1_0 calls it after validating a logon, and the filter
can only veto: it refuses a network logon for an enrolled account with
`STATUS_INVALID_WORKSTATION` and allows everything else, including pass-through
logons. MSV1_0 keeps the password check, account restrictions and token. The
filter identifies the account by its SAM RID (which survives a rename) with one
registry read, and never touches password hashes or challenge-response data.

Notes on the filter:

- Like the deny right, it blocks RDP with NLA for enrolled accounts.
- Microsoft documents `Auth0` for domain controllers. Whether MSV1_0 calls it
  for local accounts on your Windows version is the first thing to check in
  the VM. `install-subauth.ps1` refuses to run on a domain controller.
- Cleartext network logons (type 8, e.g. WinRM or IIS with Basic auth) most
  likely arrive as an interactive logon level and pass. Untested: check which
  LogonLevel arrives and whether the network deny right catches type 8.
- MSV1_0 loads the DLL on first use, so a broken filter can show up at the
  first network logon after reboot.
- `install-subauth.ps1` removes the `Auth1..4` registration of earlier
  versions, which used the wrong hook.

Both LSA pieces follow `lsasafe.h`: no heap or CRT of our own on the logon
path, SEH around the decision, and an unreadable enrollment index counts as
"enrolled" (fail closed). They link only `store_index.cpp` from the store.

```powershell
.\install-authpackage.ps1     # the authentication package
.\install-subauth.ps1         # the sub-authentication filter
& "C:\Program Files\TheAdminCafe\enroll.exe" /reindex
# ... reboot to load. uninstall-*.ps1 + reboot to remove.
```

> The LSA DLLs run in `lsass.exe`. A bug can leave the machine unbootable past
> Safe Mode. Load them only in a throwaway VM with a snapshot, a BitLocker
> recovery key and a WinRE way to edit the registry offline, and debug over a
> kernel debugger. They are learning skeletons, untested on live LSA. With LSA
> protection (RunAsPPL) on, the default on new enterprise-joined Windows 11
> 22H2+ installs with HVCI, lsass refuses to load them because they are not
> signed (see the article "2FA inside LSA"). The install scripts refuse to run
> while LSA protection is on; they check `RunAsPPL`/`RunAsPPLBoot` and WinInit
> event 12 since the last boot.

## Limits

- The tile protects only interactive logon and unlock of local accounts.
- Lock after 5 wrong codes (5, 10, 20, 40, then 60 minutes), counted only after
  a correct password. Codes can't be reused, also across parallel logons. The
  RDP client address in the events is what the client reports about itself.
- Because the password is checked first, the tile reveals whether it was right
  before the code, as the built-in tile does. The account lockout policy limits
  guessing it.
- The secrets are DPAPI-protected with the machine key and readable by SYSTEM
  and Administrators. Anyone with admin rights, or a backup of the registry and
  the machine key, can read every TOTP secret.

## Tests

`tests/totp_check.py` checks the algorithm against RFC 6238.
`make -C tests/native` builds two Linux tests: `test_verify` (real `totp.cpp` and
`verify.cpp`, checks lockout, replay and fail-closed behaviour) and `test_lsa`
(real `subauth.cpp`, `ap.cpp` and `store_index.cpp` against a fake registry,
event log and LSA heap, under AddressSanitizer and UBSan). SEH is mapped to C++
exceptions there, so the real `__except` still needs the VM.

`.github/workflows/build.yml` runs both, parses every PowerShell script and
builds everything with MSVC (`/W4 /sdl /guard:cf /CETCOMPAT`) on each push,
with `/analyze` over all sources (`/WX` for the lsass code). None of this loads
anything into LogonUI or lsass.

## License

MIT, see [LICENSE](LICENSE).
