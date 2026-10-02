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

Add the secret to your authenticator app. Log off, click "Sign-in options",
choose the brown **2FA** icon and log on with password and code.

Only when this works for every account, hide all other sign-in options:

```powershell
reg import .\register-filter.reg
```

Unlock a user after too many wrong codes: `enroll.exe /unlock alice`.
Remove an enrollment again: `enroll.exe /remove alice`. That drops the secret,
the state and the name entry the LSA packages read. Use it before you delete the
Windows account, or that name keeps being treated as enrolled - `/remove` still
cleans it up afterwards, but only if you remember the name.
Uninstall: `reg import .\unregister.reg`, reboot, delete the folder.

## Closing the non-interactive paths

The credential provider only sees the logon screen. The paths it can't reach
(network, `runas`, scheduled tasks, WinRM) are covered three ways, from safest
to most educational.

**1. User rights (supported, use this on real machines).** Denies network,
batch, service and RDP logon for an enrolled account; the console logon with the
2FA tile still works:

```powershell
.\deny-noninteractive.ps1 alice
```

**2. The LSA authentication package** (`ap.cpp`, `TacAuthPackage.dll`). Runs in
`lsass.exe` and denies non-interactive logons that are addressed to it. The
account check is implemented: it reads only the user name from the logon buffer
(bounds-checked) and asks the store, with a single registry read, whether that
name is enrolled - no DPAPI decrypt and no name/SID lookup, so nothing re-enters
LSA from the logon path. It never reads the password. A top-level package only
sees logons that select it, which is why network logons need the next piece.

**3. The MSV1_0 sub-authentication package** (`subauth.cpp`, `TacSubAuth.dll`).
MSV1_0 calls it during its own logon processing, so it sees MSV1_0's network
logons. It returns a decision - refuse a network logon for an enrolled account,
approve everything else - and **MSV1_0 keeps doing the password check and the
token**. The enrollment check is the same single registry read (no DPAPI, no
lookup), safe to run inside MSV1_0. It reads only the account name; it never
touches the password hash or the challenge-response. That credential-safety line
is the whole point: the same LSA seam is where credential-theft malware sits, and
this code deliberately does not read or keep credential material.

```powershell
.\install-authpackage.ps1     # the authentication package
.\install-subauth.ps1         # the sub-authentication package
# ... reboot to load. uninstall-*.ps1 + reboot to remove.
```

> The LSA DLLs run in `lsass.exe`. A bug can leave the machine unbootable past
> Safe Mode. Load them only in a throwaway VM with a snapshot, a BitLocker
> recovery key and a WinRE way to edit the registry offline. Debug over a kernel
> debugger. They are **learning skeletons, untested on live LSA.** See the
> article "2FA inside LSA".

## Limits

- The tile protects only interactive logon and unlock of **local** accounts.
  Network logon, `runas`, UAC, WinRM and scheduled tasks don't go through it -
  close them with `deny-noninteractive.ps1` or the LSA packages above.
- Safe Mode and offline access go around the credential provider. Use BitLocker
  (TPM + PIN) and a UEFI password.
- Lock after 5 wrong codes (5, 10, 20, 40, then 60 minutes). Codes can't be
  reused. All attempts are logged in the Application log
  (source "TheAdminCafe 2FA").

## License

MIT, see [LICENSE](LICENSE).
