#include "totp.h"
#include "store.h"
#include "statelock.h"
#include <bcrypt.h>
#include <conio.h>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

// The otpauth label is UTF-8 and percent-encoded, so names like "jürg" survive.
static std::string UrlEncode(const std::wstring& text)
{
    int cb = WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string utf8(cb > 1 ? cb - 1 : 0, '\0');
    if (cb > 1)
        WideCharToMultiByte(CP_UTF8, 0, text.c_str(), -1, &utf8[0], cb, nullptr, nullptr);

    static const char hex[] = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : utf8)
    {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
            out += static_cast<char>(c);
        else
        {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0x0F];
        }
    }
    return out;
}

// Resets the lock of an enrolled user. The last used time step stays, so an
// unlock never makes an old code valid again.
static int Unlock(const std::wstring& user, const std::wstring& sid)
{
    tac::StateLock lock;
    if (!lock.Held())
    {
        wprintf(L"Could not take the state lock. Run this elevated, from the install folder.\n");
        return 1;
    }

    tac::UserState state;
    if (!tac::LoadState(sid, state))
    {
        wprintf(L"Could not read the state of '%s'. Run this from an elevated prompt.\n", user.c_str());
        return 1;
    }

    uint64_t now = static_cast<uint64_t>(time(nullptr));
    wprintf(L"'%s': %u wrong code(s) in a row, %s.\n", user.c_str(), state.failures,
            state.lockedUntil > now ? L"locked" : L"not locked");

    state.failures    = 0;
    state.lockedUntil = 0;
    if (!tac::SaveState(sid, state))
    {
        wprintf(L"Could not reset the state. Run this from an elevated prompt.\n");
        return 1;
    }
    wprintf(L"Unlocked.\n");
    return 0;
}

// Removes an enrollment: the secret, the state and the name-keyed index the LSA
// packages read. The account does not have to exist anymore. If it was already
// deleted in Windows we cannot resolve a SID, but we can still drop the name
// entry, and that is the one that would otherwise keep denying network logons.
static int Remove(const std::wstring& user, const std::wstring& sid)
{
    if (sid.empty())
        wprintf(L"'%s' is not a local user account (anymore). Removing the name entry only.\n",
                user.c_str());

    if (!tac::RemoveEnrollment(user, sid))
    {
        wprintf(L"Could not remove the enrollment of '%s'. Run this from an elevated prompt.\n",
                user.c_str());
        return 1;
    }

    wprintf(L"Removed the enrollment of '%s'.\n", user.c_str());
    wprintf(L"The account can log on with its password alone again, unless you also\n");
    wprintf(L"set the deny rights (deny-noninteractive.ps1).\n");
    return 0;
}

// Rebuilds the RID and name indexes the LSA packages read, from the stored
// secrets. Needed once after updating from a version without the RID index,
// and after renaming an enrolled account.
static int Reindex()
{
    int count = tac::ReindexEnrollments();
    if (count < 0)
    {
        wprintf(L"Could not read the enrollments or write the index. Run this from an elevated prompt.\n");
        return 1;
    }
    wprintf(L"Indexed %d enrollment(s).\n", count);
    return 0;
}

// Reads one line from the console, at most `max` characters.
static std::wstring ReadLine(size_t max)
{
    wchar_t buf[64] = {};
    if (!fgetws(buf, ARRAYSIZE(buf), stdin))
        return std::wstring();
    std::wstring line(buf);
    SecureZeroMemory(buf, sizeof(buf));
    while (!line.empty() && (line.back() == L'\n' || line.back() == L'\r' || line.back() == L' '))
        line.pop_back();
    if (line.size() > max)
        line.clear();
    return line;
}

// Asks for a code from the authenticator app before anything is stored. A
// secret that was mistyped into the app would otherwise lock the account out
// at the next logon. On success `step` is the time step of the code, so the
// same code cannot be used again at the logon screen.
static bool ConfirmSecret(const std::string& secret, uint64_t& step)
{
    std::vector<BYTE> key;
    if (!tac::Base32Decode(secret, key))
        return false;

    bool ok = false;
    for (int attempt = 1; attempt <= 3 && !ok; ++attempt)
    {
        wprintf(L"Enter the 6-digit code from your authenticator app (attempt %d of 3): ", attempt);
        std::wstring code = ReadLine(16);
        ok = tac::ValidateTotp(key, code, static_cast<uint64_t>(time(nullptr)), 0, step);
        if (!code.empty())
            SecureZeroMemory(&code[0], code.size() * sizeof(WCHAR));
        if (!ok)
            wprintf(L"That code does not match. Check the secret in the app and the clock of both devices.\n");
    }
    SecureZeroMemory(key.data(), key.size());
    return ok;
}

// Deletes every secret, state and index entry. For a full uninstall; the
// provider registration itself is removed by unregister.reg.
static int Purge()
{
    bool any = false;
    if (tac::QueryAnyEnrollment(any) && any)
    {
        wprintf(L"This deletes ALL 2FA secrets and state on this machine. If the filter is\n");
        wprintf(L"still registered, the other sign-in options come back immediately.\n");
        wprintf(L"Continue? [y/N] ");
        int answer = _getwch();
        wprintf(L"\n");
        if (answer != L'y' && answer != L'Y')
        {
            wprintf(L"Aborted.\n");
            return 0;
        }
    }

    if (!tac::PurgeAllEnrollments())
    {
        wprintf(L"Could not delete HKLM\\SOFTWARE\\TheAdminCafe\\2FA. Run this from an elevated prompt.\n");
        return 1;
    }
    wprintf(L"All 2FA data removed.\n");
    return 0;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && _wcsicmp(argv[1], L"/reindex") == 0)
        return Reindex();
    if (argc == 2 && _wcsicmp(argv[1], L"/purge") == 0)
        return Purge();

    bool unlock = argc == 3 && _wcsicmp(argv[1], L"/unlock") == 0;
    bool remove = argc == 3 && _wcsicmp(argv[1], L"/remove") == 0;
    if ((argc != 2 && !unlock && !remove) || (argc == 2 && argv[1][0] == L'/'))
    {
        wprintf(L"Usage: enroll <local username>\n");
        wprintf(L"       enroll /unlock <local username>\n");
        wprintf(L"       enroll /remove <local username>\n");
        wprintf(L"       enroll /reindex\n");
        wprintf(L"       enroll /purge          (delete all 2FA data)\n");
        return 1;
    }

    // Only names that exist as a local user account on this machine. The
    // secret is stored under the SID of that account.
    std::wstring user = tac::NormalizeUser(argv[(unlock || remove) ? 2 : 1]);
    std::wstring sid;
    if (!tac::ResolveLocalUserSid(user, sid))
    {
        // For /remove an unresolvable name is not fatal: the name-keyed index
        // entry can and should still go. Everything else needs the SID.
        if (!remove)
        {
            wprintf(L"'%s' is not a local user account on this machine.\n", user.c_str());
            return 1;
        }
        sid.clear();
    }

    if (unlock)
        return Unlock(user, sid);
    if (remove)
        return Remove(user, sid);

    std::vector<BYTE> existing;
    if (tac::LoadSecretKey(sid, existing))
    {
        SecureZeroMemory(existing.data(), existing.size());
        wprintf(L"'%s' is already enrolled. Replace the secret? [y/N] ", user.c_str());
        int answer = _getwch();
        wprintf(L"\n");
        if (answer != L'y' && answer != L'Y')
        {
            wprintf(L"Aborted.\n");
            return 0;
        }
    }

    // 160 bits, the key size RFC 4226 recommends for HMAC-SHA1.
    BYTE raw[20];
    if (BCryptGenRandom(nullptr, raw, sizeof(raw), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
    {
        wprintf(L"Could not generate a random secret.\n");
        return 1;
    }
    std::string secret = tac::Base32Encode(raw, sizeof(raw));
    SecureZeroMemory(raw, sizeof(raw));

    std::string uri = "otpauth://totp/TheAdminCafe:" + UrlEncode(user) +
                      "?secret=" + secret +
                      "&issuer=TheAdminCafe&algorithm=SHA1&digits=6&period=30";

    // Show the secret first and store it only after a code from the app
    // matches. Until then nothing is written, and an existing enrollment
    // keeps working.
    wprintf(L"\nNew secret for '%s' (%s):\n\n", user.c_str(), sid.c_str());
    wprintf(L"  Secret : %S\n", secret.c_str());
    wprintf(L"  URI    : %S\n\n", uri.c_str());
    wprintf(L"Add the secret to your authenticator app. Don't paste it into an online\n");
    wprintf(L"QR code generator.\n\n");
    SecureZeroMemory(&uri[0], uri.size());

    uint64_t confirmedStep = 0;
    if (!ConfirmSecret(secret, confirmedStep))
    {
        wprintf(L"\nNot enrolled: no matching code. Nothing was changed.\n");
        SecureZeroMemory(&secret[0], secret.size());
        return 1;
    }

    // A new secret starts with a clean state: no lock, and the confirmation
    // code counts as used. The two steps are reported separately, because "the
    // secret is stored but the old state is still there" is a different
    // situation from "nothing was written" and needs a different fix.
    if (!tac::StoreSecret(sid, secret))
    {
        wprintf(L"Could not store the secret. Run this from an elevated prompt.\n");
        wprintf(L"An earlier enrollment of '%s', if any, is unchanged.\n", user.c_str());
        SecureZeroMemory(&secret[0], secret.size());
        return 1;
    }
    SecureZeroMemory(&secret[0], secret.size());

    tac::UserState fresh = {};
    fresh.lastStep = confirmedStep;
    tac::StateLock lock;
    if (!lock.Held() || !tac::SaveState(sid, fresh))
    {
        wprintf(L"The secret was stored, but the old lockout state of '%s' could not be\n", user.c_str());
        wprintf(L"reset. Run 'enroll /unlock %s' from an elevated prompt.\n", user.c_str());
        return 1;
    }

    wprintf(L"\nEnrolled '%s'. Test the logon now, before you import the filter.\n", user.c_str());
    wprintf(L"Clear this window afterwards (cls), the secret is still in the scrollback.\n");
    return 0;
}
