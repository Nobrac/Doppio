# Doppio ☕☕

**Two shots for your Windows logon.** A TOTP second factor for **local** Windows
accounts, built as a Credential Provider. Password + 6-digit code from any
authenticator app, at the logon and unlock screen - locally and over RDP.

This is a **learning demo**, not a product. It is the code companion to the
blog article "Build Your Own Working 2FA for Local Windows Logon" on
TheAdminCafe, which explains every line of it.

> **Build and run this only in a throwaway VM, with a snapshot before every
> install.** A broken credential provider - or a filter that hides every other
> tile - locks you out of the machine with no stack trace. Keep a break-glass
> admin account and a snapshot at all times.

## Quick start

From the "x64 Native Tools Command Prompt" of Visual Studio:

```bat
build.bat
```

Then, in an elevated PowerShell on the test VM:

```powershell
New-Item -ItemType Directory -Force "C:\Program Files\TheAdminCafe" | Out-Null
Copy-Item .\TacProvider.dll, .\enroll.exe "C:\Program Files\TheAdminCafe\"
reg import .\register.reg
& "C:\Program Files\TheAdminCafe\enroll.exe" <local user>
# log off, "Sign-in options" -> brown "2FA" icon, test it.
# Only when every account works:
reg import .\register-filter.reg
```

Run `new-guids.ps1` once before you use this anywhere, so you don't share the
CLSIDs of this repository.

## What it does (and does not) do

- **Does:** requires a valid RFC 6238 TOTP, in addition to the password, to log
  in or unlock interactively. With the filter registered, no other tile
  (password, PIN, Hello) is offered.
- **Does not:** cover network logon, `runas`, scheduled tasks, WinRM/WMI, or UAC
  credential prompts (a user who knows a local admin password can still elevate). Those
  paths never touch this provider. Close them with local-account network-logon
  restrictions. See the article's "limits" section.
- **Does not:** survive physical access on its own. Third-party credential
  providers are not loaded in Safe Mode, and without BitLocker anyone can edit
  the registry offline. Use BitLocker (TPM + PIN) and a UEFI password.

## Files

| File | Purpose |
|------|---------|
| `guid.h` | CLSIDs for the provider and filter. **Regenerate before shipping.** |
| `common.h` | Field layout (username, password, OTP, submit) and field states. |
| `helpers.h/.cpp` | KERB serialization pack/unpack, Negotiate lookup, field copy. |
| `CTacProvider.h/.cpp` | `ICredentialProvider` + `ICredentialProviderSetUserArray`: one tile per local user, fallback tile, RDP intake. |
| `CTacCredential.h/.cpp` | `ICredentialProviderCredential2`: a user tile (`GetUserSid`); `GetSerialization` checks the code. |
| `CTacFilter.h/.cpp` | `ICredentialProviderFilter`: hides other providers, forwards RDP credentials. |
| `dll.h/.cpp` | Class factory + COM exports; defines the GUIDs. |
| `TacProvider.def` | Exports `DllGetClassObject`, `DllCanUnloadNow`. |
| `totp.h/.cpp` | RFC 6238 TOTP over CNG (bcrypt). Unit-test against RFC vectors first. |
| `store.h/.cpp` | DPAPI (machine-scope) secret store with an ACL'd HKLM key, keyed by SID; per-account state (last step, failures, lock). |
| `verify.h/.cpp` | Replay protection and lock after 5 wrong codes (5, 10, 20, 40, then 60 minutes). |
| `eventlog.h/.cpp` | Events 100-106 in the Application log, source "TheAdminCafe 2FA". |
| `enroll.cpp` | Console tool: mint a secret, print an `otpauth://` URI, store it. `/unlock <user>` clears a lock. |
| `register.reg` | COM + provider registration (no filter). |
| `register-filter.reg` | The filter. Import last. |
| `unregister.reg` | Removes everything except the secrets. |
| `new-guids.ps1` | Creates new CLSIDs and writes them into `guid.h` and all `.reg` files. |

## Prerequisites

- Visual Studio 2026 or 2022 (Community is enough) or the Build Tools, with the
  **Desktop development with C++** workload (includes the compiler and the Windows SDK).
- Nothing extra on the test VM: the runtime is linked statically (`/MT`).
- Build **x64**, Release or Debug.

## Building

Two outputs from the same sources.

**`TacProvider.dll`** (the provider + filter):
- Sources: `dll.cpp`, `CTacProvider.cpp`, `CTacCredential.cpp`, `CTacFilter.cpp`,
  `helpers.cpp`, `totp.cpp`, `store.cpp`, `verify.cpp`, `eventlog.cpp`.
- Configuration type: **Dynamic Library (.dll)**.
- Module definition file: **`TacProvider.def`** (Linker → Input → Module Definition File).
- Libraries are pulled in via `#pragma comment(lib, ...)` in the sources
  (`bcrypt`, `crypt32`, `advapi32`, `secur32`, `shlwapi`, `wtsapi32`); the SDK's `uuid.lib`
  (linked by default) supplies the interface IIDs.

**`enroll.exe`** (the enrollment tool):
- Sources: `enroll.cpp`, `totp.cpp`, `store.cpp`.
- Configuration type: **Application (.exe)**.

> Tip: build `totp.cpp` into a tiny test harness first and check it against the
> RFC 6238 appendix B test vectors. Debugging crypto on the Secure Desktop is
> not where you want to discover an endianness bug.

## Deploying

1. Take a VM snapshot.
2. Create `C:\Program Files\TheAdminCafe\` and copy `TacProvider.dll` and
   `enroll.exe` into it. Do not use a folder directly under `C:\`: those inherit
   rights that let any user replace the DLL, which LogonUI loads as SYSTEM.
3. Import `register.reg` from an elevated prompt: `reg import register.reg`.
   This registers the provider but hides nothing.
4. Sign out. Click a user, then "Sign-in options": the brown "2FA" icon is
   our provider, next to password and PIN.

## Enrolling and testing

```
net user alice <password> /add
"C:\Program Files\TheAdminCafe\enroll.exe" alice
```

Add the secret to an authenticator app, sign out and log in with alice's
password **and** the current code. Make sure the VM clock is correct, otherwise
every code is rejected.

Once that works for every account you need (including a break-glass admin),
import `register-filter.reg` and sign out again. Now every user tile asks for
password and code, and the other sign-in options are gone.

## Recovery / uninstall

- Uninstall: `reg import unregister.reg`, reboot, then delete the folder under
  Program Files. Secrets and lock state stay in `HKLM\SOFTWARE\TheAdminCafe` until you delete it.
- Too many wrong codes: `enroll.exe /unlock <user>` from an elevated prompt, or
  wait (at most 60 minutes).
- Locked out: restore the snapshot, or boot into the Windows Recovery
  Environment and delete the filter key from the offline `SOFTWARE` hive.

## Honest caveats about this code

- **Tile image and name:** each tile is bound to a user (v2 tile via
  `GetUserSid`), so Windows draws the account name and its round picture itself.
- **`ProtectIfNecessaryAndCopyPassword`** keeps a plain copy of the password
  instead of `CredProtect`-ing it, to stay small and correct for local logon.
  The Microsoft sample's version is stronger.
- **The remote/NLA path** (`UpdateRemoteCredential` + `SetSerialization`) is
  implemented but is the least-tested path here; verify it in your environment
  before relying on it.
- **Replay protection and rate limiting** live in `verify.cpp`. The state is
  read and written from each LogonUI process without a cross-session lock, so
  parallel RDP sessions can each get one extra guess past a lock.
- **No TPM-bound secret.** The registry ACL - not DPAPI's machine scope - is
  what keeps ordinary users away from the ciphertext. Any copy of the SOFTWARE
  hive can be decrypted on this machine.
- **Secrets from older versions** were stored under the user name. They are
  no longer found; enroll the users again.

The serialization helpers in `helpers.cpp` are trimmed reimplementations of
Microsoft's credential-provider sample helpers (Windows-classic-samples,
`Security/CredentialProvider`); consult that sample for the fuller versions.

## License

MIT, see [LICENSE](LICENSE). No warranty: this code runs as SYSTEM inside
LogonUI and can lock you out of your machine.
