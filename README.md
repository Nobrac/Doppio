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
New-Item -ItemType Directory -Force "C:\Program Files\TheAdminCafe" | Out-Null
Copy-Item .\TacProvider.dll, .\enroll.exe "C:\Program Files\TheAdminCafe\"
reg import .\register.reg

# Enroll every local account you need, including a break-glass admin
& "C:\Program Files\TheAdminCafe\enroll.exe" alice
```

`enroll.exe` shows the secret and asks for a code from your authenticator app
before it stores anything, so a secret mistyped into the app can't lock you
out. Log off, click "Sign-in options", choose the brown **2FA** icon and log on
with password and code.

Only when this works for every account, hide all other sign-in options:

```powershell
reg import .\register-filter.reg
```

From then on the logon and unlock screens show **only** the 2FA tiles - no
password tile, no PIN, no Windows Hello. That is the point: with any of them
left, the code would be optional. Microsoft advises against it, because a
broken provider then leaves no way in. What is left for recovery:

- The 2FA provider always shows an **"Other user"** tile at logon, so an
  account Windows does not list (a hidden break-glass admin) can still sign in.
- While **no account is enrolled at all**, the filter hides nothing. Importing
  it too early, or after `enroll.exe /purge`, cannot lock you out.
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
Remove an enrollment again: `enroll.exe /remove alice`. That drops the secret,
the state and the index entries the LSA packages read. Use it before you delete
the Windows account; `/remove` still cleans up afterwards, but only if you
remember the name. After renaming an enrolled account, or after updating from a
version without the RID index, run `enroll.exe /reindex`.
Uninstall: `enroll.exe /purge` (deletes all secrets, state and indexes), then
`reg import .\unregister.reg`, reboot, delete the folder (it also holds
`state.lock`, which serializes the state updates of parallel logons). Without
`/purge`, the secrets stay in the registry and come back on a reinstall.

Events (Application log, source "TheAdminCafe 2FA"): 100 password and code
accepted, 101 wrong code, 102 code already used, 103/104 lock, 105 not
enrolled, 106 state error, 107 password refused, 108 final result from LSA.

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
logon fails anyway, because the package never builds a token. It reads only the
user name from the logon buffer (bounds-checked), never the password, and asks
the store with a single registry read whether that name is enrolled - no DPAPI
decrypt and no name/SID lookup, so nothing re-enters LSA from the logon path.

**3. The MSV1_0 sub-authentication filter** (`subauth.cpp`, `TacSubAuth.dll`,
registered as `Auth0`). MSV1_0 calls it **after** it has validated a logon, and
the filter can only veto: it refuses a network logon for an enrolled account and
has no objection to anything else. MSV1_0 keeps the password check, the account
restrictions and the token. The account is identified by the RID from the SAM,
which survives a rename, with a single registry read (no DPAPI, no lookup). It
reads nothing but the RID and the account name; it never touches the password
hashes or the challenge-response. That credential-safety line is the whole
point: the same LSA seam is where credential-theft malware sits, and this code
deliberately does not read or keep credential material.

Earlier versions exported `Msv1_0SubAuthenticationRoutine` under `Auth1..4`.
That is the wrong hook: it only runs for logons that ask for it, and when it
runs, the password check is *its* job - "approve" there meant "approve without a
password". `install-subauth.ps1` removes the old registration.

Like the deny right, the filter also blocks RDP with NLA for enrolled accounts.
Microsoft documents `Auth0` for domain controllers; whether MSV1_0 calls it for
local accounts on your Windows version is the first thing to check in the VM.

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
> protection (RunAsPPL) on - the default on many current Windows 11 installs -
> lsass refuses to load them at all, because they are not signed. See the
> article "2FA inside LSA". The install scripts refuse to run while LSA
> protection is on (registry check).

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

`tests/totp_check.py` checks the algorithm against RFC 6238 in Python.
`tests/native/` compiles the real `totp.cpp` and `verify.cpp` on Linux, against
OpenSSL and an in-memory store, and checks the lockout, replay and fail-closed
behaviour: `make -C tests/native`. `.github/workflows/build.yml` runs both, and
builds everything with MSVC (`/W4 /sdl /guard:cf`, plus `/analyze`) on each push.
None of this loads anything into LogonUI or lsass; that still needs the VM.

## License

MIT, see [LICENSE](LICENSE).
