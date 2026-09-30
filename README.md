# Doppio ☕☕

**Two shots for your Windows logon.** A TOTP second factor for local Windows
accounts, built as a Credential Provider: password + 6-digit code from any
authenticator app, at logon and unlock, locally and over RDP.

> **Learning demo, not a product.** Use it only in a throwaway VM with a
> snapshot. A broken credential provider can lock you out of the machine.

## Build

From the "x64 Native Tools Command Prompt" of Visual Studio:

```bat
build.bat
```

Output: `TacProvider.dll` and `enroll.exe`. Run `new-guids.ps1` once before,
so you don't use the CLSIDs of this repository.

## Install

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
Uninstall: `reg import .\unregister.reg`, reboot, delete the folder.

## Limits

- Protects only interactive logon and unlock of **local** accounts. Network
  logon, `runas`, UAC, WinRM and scheduled tasks don't go through the tile.
- Safe Mode and offline access go around any credential provider. Use
  BitLocker (TPM + PIN) and a UEFI password.
- Lock after 5 wrong codes (5, 10, 20, 40, then 60 minutes). Codes can't be
  reused. All attempts are logged in the Application log
  (source "TheAdminCafe 2FA").

## License

MIT, see [LICENSE](LICENSE).
