# Doppio ☕☕

**Two shots for your Windows logon.** A TOTP second factor for local Windows
accounts, built as a Credential Provider: password + 6-digit code from any
authenticator app, at logon and unlock, locally and over RDP.

> **Learning demo, not a product.** Use it only in a throwaway VM with a
> snapshot. A broken credential provider can lock you out of the machine, and
> the LSA pieces below can leave it unbootable.

## Build

From the "x64 Native Tools Command Prompt" of Visual Studio:

```bat
build.bat
```

Output: `TacProvider.dll`, `enroll.exe`, and the two LSA skeletons
`TacAuthPackage.dll` and `TacSubAuth.dll`. Run `new-guids.ps1` once before you
use this anywhere, so you don't use the CLSIDs of this repository.

## Install (the credential provider)

In an elevated PowerShell on the test VM:

```powershell
.\install-doppio.ps1

# Enroll every local account that signs in at the console or over RDP,
# including a break-glass admin
& "C:\Program Files\TheAdminCafe\enroll.exe" alice
& "C:\Program Files\TheAdminCafe\enroll.exe" breakglass
```

`install-doppio.ps1` copies the files to `C:\Program Files\TheAdminCafe` and
imports `register.reg`, after checking that nobody else's provider already
holds those CLSIDs. (By hand: create the folder, copy `TacProvider.dll` and
`enroll.exe`, `reg import .\register.reg`.)

`enroll.exe` shows the secret and asks for a code from your authenticator app
before it stores anything, so a secret mistyped into the app can't lock you
out. Log off, click "Sign-in options", choose the brown **2FA** icon and log on
with password and code.

Only when this works for every account, hide all other sign-in options:

```powershell
.\install-doppio.ps1 -EnableFilter
```

It refuses while an enabled local account is not enrolled, because that account
could not sign in at the console or over RDP afterwards. An account that never
signs in interactively (a service account) can be named with
`-AllowUnenrolled svc-backup`. (By hand: `reg import .\register-filter.reg`,
without that check.)

From then on the logon and unlock screens show **only** the 2FA tiles - no
password tile, no PIN, no Windows Hello. That is the point: with any of them
left, the code would be optional. Microsoft advises against it, because a
broken provider then leaves no way in. What is left for recovery:

- The 2FA provider always shows an **"Other user"** tile at logon, so an
  account Windows does not list (a hidden break-glass admin) can still sign in.
- While **no account is enrolled at all**, the filter hides nothing. Importing
  it too early, or after `enroll.exe /purge`, cannot lock you out. Only stored
  secrets count, not stray registry values - but the secret of an account you
  deleted without `/remove` does count. `enroll.exe /list` shows it as
  "(deleted account)"; `enroll.exe /remove <SID>` removes it.
- If `TacProvider.dll` cannot be loaded, the filter in the same DLL cannot be
  created either, and Windows shows all sign-in options again. Confirm this once
  in the VM by renaming the DLL.
- Otherwise: boot WinRE, load the SOFTWARE hive offline and delete
  `Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{B1E7C9A0-2F4D-4C6B-9A11-0000C0FFEE02}`
  (your GUID after `new-guids.ps1`). Practise this before you need it.

The tile checks the **password first** and looks at the code only when the
password was right. Wrong passwords are counted by Windows, so set an account
lockout policy as you would without this tile. Wrong codes are counted by the
tile. Nobody can lock an account by typing random codes without knowing its
password. The password check is a `LogonUser` call, so each sign-in leaves one
extra logon event (4624, type 2, LogonUI.exe) in the Security log.

Unlock a user after too many wrong codes: `enroll.exe /unlock alice`.
See who is enrolled, and whether the LSA indexes know about them:
`enroll.exe /list`. Remove an enrollment again: `enroll.exe /remove alice`.
That drops the secret, the state and the index entries the LSA packages read.
Use it before you delete the Windows account; afterwards, take the SID from
`/list` and run `enroll.exe /remove S-1-5-21-...`. After renaming an enrolled
account, or after updating from a version without the RID index, run
`enroll.exe /reindex`. Every `enroll.exe` run (except `/list` and `/purge`) also
re-applies the SYSTEM-and-Administrators ACL to existing store keys; the logon
path no longer does that on every attempt.
Uninstall: `enroll.exe /purge` (deletes all secrets, state and indexes), then
`reg import .\unregister.reg`, reboot, delete the folder (it also holds
`state.lock`, which serializes the state updates of parallel logons). Without
`/purge`, the secrets stay in the registry and come back on a reinstall.

Events (Application log, source "TheAdminCafe 2FA"): 100 password and code
accepted, 101 wrong code, 102 code already used, 103/104 lock, 105 not
enrolled, 106 state error, 107 password refused, 108 final result from LSA.
From the LSA pieces: 200 authentication package loaded (written while LSA
starts, before the Eventlog service runs, so usually only visible in the
debugger), 201/202 package denied/declined a logon, 210 filter refused a logon.

## What the tile does not cover

The credential provider only sees the logon and unlock screens. These still
take the password alone, whatever else you install:

- `runas`, the **UAC credential prompt** and any program calling `LogonUser`
  interactively. They are interactive logons without a logon screen. No user
  right separates them from the console logon, and the filter below does not
  see them.
- Safe Mode and offline access. Use BitLocker (TPM + PIN) and a UEFI password.

## Closing the non-interactive paths

Network logon (SMB, WinRM), scheduled tasks and services don't reach the tile
either. They are covered three ways, from safest to most educational.

**1. User rights (supported, use this on real machines).** Denies network,
batch and service logon for an enrolled account; the console logon with the
2FA tile still works:

```powershell
.\deny-noninteractive.ps1 alice
```

RDP with **Network Level Authentication** (the default) checks the password
with a network logon before the session starts, so denying network logon also
blocks NLA for that account. Either use the console, turn NLA off (RDP then goes
straight to the 2FA tile, with more attack surface on the RDP port), or run the
script with `-KeepNetwork` and accept that SMB/WinRM still take the password
alone. On a domain member, a GPO that defines these rights overwrites them.

**2. The LSA authentication package** (`ap.cpp`, `TacAuthPackage.dll`). Runs in
`lsass.exe` and shows the package interface. It is **not a security control**:
a logon only reaches it if the caller selects it by package id, and every such
logon fails anyway, because the package never builds a token - denied with
`STATUS_ACCOUNT_RESTRICTION` for an enrolled account on a non-interactive path,
declined with `STATUS_INVALID_LOGON_TYPE` otherwise. It reads only the user
name from the logon buffer (bounds-checked, as a client address or a packed
offset), never the password, returns it as `AccountName` for the audit record,
and asks the store with a single registry read whether that name is enrolled -
no DPAPI decrypt and no name/SID lookup, so nothing re-enters LSA from the
logon path.

**3. The MSV1_0 sub-authentication filter** (`subauth.cpp`, `TacSubAuth.dll`,
registered as `Auth0`). MSV1_0 calls it **after** it has validated a logon, and
the filter can only veto: it refuses a network logon for an enrolled account
with `STATUS_INVALID_WORKSTATION` and has no objection to anything else, nor to
a pass-through logon for an account that lives elsewhere. MSV1_0 keeps the
password check, the account restrictions and the token. The account is
identified by the RID from the SAM, which survives a rename, with a single
registry read (no DPAPI, no lookup). It reads nothing but the RID and the
account name; it never touches the password hashes or the challenge-response.
That credential-safety line is the whole point: the same LSA seam is where
credential-theft malware sits, and this code deliberately does not read or keep
credential material.

Both LSA pieces follow the same rules (`lsasafe.h`): no heap and no CRT of our
own on the logon path, SEH around the decision, and an enrollment index that
cannot be read counts as "enrolled" (fail closed). They link only
`store_index.cpp` from the store, not the DPAPI and TOTP code.

The filter leaves `LogoffTime` and `KickoffTime` alone; what MSV1_0 hands in
there is undocumented, so every call writes the incoming values to the
debugger. Logons where the server gets the password in clear (type 8,
NetworkCleartext, e.g. WinRM or IIS with Basic auth) most likely reach the
filter as an interactive logon level and get no objection - check that in the
VM before you rely on it, and keep the deny rights for those paths.

Earlier versions exported `Msv1_0SubAuthenticationRoutine` under `Auth1..4`.
That is the wrong hook: it only runs for logons that ask for it, and when it
runs, the password check is *its* job - "approve" there meant "approve without a
password". `install-subauth.ps1` removes the old registration.

Like the deny right, the filter also blocks RDP with NLA for enrolled accounts.
Microsoft documents `Auth0` for domain controllers; whether MSV1_0 calls it for
local accounts on your Windows version is the first thing to check in the VM.
`install-subauth.ps1` refuses to run on a domain controller, where the filter
would check domain RIDs against a local index. MSV1_0 loads the DLL the first
time it needs it, so a broken filter can surface at the first network logon
after the reboot, not only at boot.

```powershell
.\install-authpackage.ps1     # the authentication package
.\install-subauth.ps1         # the sub-authentication filter
& "C:\Program Files\TheAdminCafe\enroll.exe" /reindex
# ... reboot to load. uninstall-*.ps1 + reboot to remove.
```

> The LSA DLLs run in `lsass.exe`. A bug can leave the machine unbootable past
> Safe Mode. Load them only in a throwaway VM with a snapshot, a BitLocker
> recovery key and a WinRE way to edit the registry offline. Debug over a kernel
> debugger. They are **learning skeletons, untested on live LSA.** With LSA
> protection (RunAsPPL) on - the default on new, enterprise-joined Windows 11
> 22H2+ installs with HVCI - lsass refuses to load them at all, because they
> are not signed. See the article "2FA inside LSA". The install scripts refuse
> to run while LSA protection is on: they check `RunAsPPL`/`RunAsPPLBoot` and,
> because the default-on case is not documented to show up there, WinInit
> event 12 ("started as a protected process") since the last boot.

## Limits

- The tile protects only interactive logon and unlock of **local** accounts.
  See "What the tile does not cover" above.
- Lock after 5 wrong codes (5, 10, 20, 40, then 60 minutes), counted only after
  a correct password. Codes can't be reused, also not across parallel logons.
  All attempts are logged in the Application log (source "TheAdminCafe 2FA").
  The RDP client address in those events is what the client reports about
  itself.
- Because the password is checked first, the tile tells whoever types it
  whether the password was right, before the code. That is the same answer the
  built-in tile gives; the account lockout policy is what limits guessing it.
- The secrets are DPAPI-protected with the machine key and readable by
  SYSTEM and Administrators. Anyone with admin rights or a backup of the
  registry and the machine key can read every TOTP secret.

## Tests

`tests/totp_check.py` checks the algorithm against RFC 6238 in Python and
exits non-zero on any failed check. `tests/native/` builds two tests on Linux
with `make -C tests/native`:

- `test_verify` compiles the real `totp.cpp` and `verify.cpp` against OpenSSL
  and an in-memory store, and checks the lockout, replay and fail-closed
  behaviour.
- `test_lsa` compiles the real `subauth.cpp`, `ap.cpp` and `store_index.cpp` -
  the code that runs inside lsass - against a fake registry, event log and LSA
  heap, under AddressSanitizer and UBSan. It checks every veto and fail-closed
  path, the `[out]` parameters, hostile logon buffers, non-ASCII names, and that
  no LSA heap block or registry handle leaks. SEH is mapped to C++ exceptions
  there, so the real `__except` still needs the VM.

`.github/workflows/build.yml` runs both, parses every PowerShell script, and
builds everything with MSVC (`/W4 /sdl /guard:cf /CETCOMPAT`) on each push.
`/analyze` runs over all sources as a report, and with `/WX` over the lsass
code, where a finding fails the build. None of this loads anything into
LogonUI or lsass; that still needs the VM.

## License

MIT, see [LICENSE](LICENSE).
