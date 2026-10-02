#include "store.h"
#include "totp.h"
#include <wincrypt.h>
#include <sddl.h>
#include <cwctype>
#include <cstdio>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace tac
{
    static const wchar_t kKeyPath[]   = L"SOFTWARE\\TheAdminCafe\\2FA";
    static const wchar_t kStatePath[] = L"SOFTWARE\\TheAdminCafe\\2FA\\State";
    // Enrollment indexes for the LSA hot path (presence only, no secret).
    static const wchar_t kNamePath[]  = L"SOFTWARE\\TheAdminCafe\\2FA\\Names";
    static const wchar_t kRidPath[]   = L"SOFTWARE\\TheAdminCafe\\2FA\\Rids";

    // SYSTEM and Administrators only. "P" blocks the inherited ACL of
    // HKLM\SOFTWARE, which would let every user read the key.
    static const wchar_t kKeySddl[] = L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";

    std::wstring NormalizeUser(const std::wstring& user)
    {
        std::wstring name = user;
        size_t pos = name.find_last_of(L'\\');
        if (pos != std::wstring::npos)
            name = name.substr(pos + 1);
        for (wchar_t& c : name)
            c = static_cast<wchar_t>(towlower(c));
        return name;
    }

    static bool Protect(const std::string& plain, std::vector<BYTE>& blob)
    {
        DATA_BLOB in  = { static_cast<DWORD>(plain.size()),
                          reinterpret_cast<BYTE*>(const_cast<char*>(plain.data())) };
        DATA_BLOB out = {};

        // Machine scope, so LogonUI (SYSTEM) can decrypt what an admin encrypted.
        if (!CryptProtectData(&in, L"tac-2fa", nullptr, nullptr, nullptr,
                              CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out))
            return false;

        blob.assign(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return true;
    }

    static bool Unprotect(const std::vector<BYTE>& blob, std::string& plain)
    {
        DATA_BLOB in  = { static_cast<DWORD>(blob.size()), const_cast<BYTE*>(blob.data()) };
        DATA_BLOB out = {};

        if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr,
                                CRYPTPROTECT_UI_FORBIDDEN, &out))
            return false;

        plain.assign(reinterpret_cast<char*>(out.pbData), out.cbData);
        SecureZeroMemory(out.pbData, out.cbData);
        LocalFree(out.pbData);
        return true;
    }

    // Resolves the name the same way LSA will: as COMPUTERNAME\name against the
    // local SAM. Only a real user account counts, not a group or an alias.
    bool ResolveLocalUserSid(const std::wstring& user, std::wstring& sid)
    {
        sid.clear();
        std::wstring name = NormalizeUser(user);
        if (name.empty())
            return false;

        WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD cchComputer = ARRAYSIZE(computer);
        if (!GetComputerNameW(computer, &cchComputer))
            return false;

        std::wstring qualified = std::wstring(computer) + L"\\" + name;
        BYTE sidBuf[SECURITY_MAX_SID_SIZE];
        DWORD cbSid = sizeof(sidBuf);
        WCHAR domain[256] = {};
        DWORD cchDomain = ARRAYSIZE(domain);
        SID_NAME_USE use;
        if (!LookupAccountNameW(nullptr, qualified.c_str(), sidBuf, &cbSid,
                                domain, &cchDomain, &use))
            return false;

        // The account has to live in this computer's SAM, not in a domain.
        if (use != SidTypeUser || _wcsicmp(domain, computer) != 0)
            return false;

        PWSTR pszSid = nullptr;
        if (!ConvertSidToStringSidW(sidBuf, &pszSid))
            return false;
        sid = pszSid;
        LocalFree(pszSid);
        return true;
    }

    // Only SIDs are used as value names. This keeps odd input out of the registry.
    static bool IsSidString(const std::wstring& sid)
    {
        return sid.size() > 4 && sid.compare(0, 4, L"S-1-") == 0;
    }

    bool RidFromSidString(const std::wstring& sid, DWORD& rid)
    {
        rid = 0;
        if (!IsSidString(sid))
            return false;
        size_t dash = sid.find_last_of(L'-');
        if (dash == std::wstring::npos || dash + 1 >= sid.size() || sid.size() - dash - 1 > 10)
            return false;

        uint64_t value = 0;
        for (size_t i = dash + 1; i < sid.size(); ++i)
        {
            if (sid[i] < L'0' || sid[i] > L'9')
                return false;
            value = value * 10 + static_cast<uint64_t>(sid[i] - L'0');
        }
        if (value == 0 || value > 0xFFFFFFFFull)
            return false;
        rid = static_cast<DWORD>(value);
        return true;
    }

    // SID string -> normalized local account name. Used only at enroll time (a
    // console app), never on the LSA hot path.
    static bool NameFromSid(const std::wstring& sidStr, std::wstring& name)
    {
        name.clear();
        PSID psid = nullptr;
        if (!ConvertStringSidToSidW(sidStr.c_str(), &psid))
            return false;

        WCHAR n[256] = {}; DWORD cn = ARRAYSIZE(n);
        WCHAR d[256] = {}; DWORD cd = ARRAYSIZE(d);
        SID_NAME_USE use;
        BOOL ok = LookupAccountSidW(nullptr, psid, n, &cn, d, &cd, &use);
        LocalFree(psid);
        if (!ok)
            return false;

        name = NormalizeUser(n);
        return !name.empty();
    }

    // Creates or opens a key below HKLM with our ACL. The security attributes
    // only apply when the key is created. An existing key might still carry a
    // weaker ACL, so it is set again.
    static LSTATUS OpenProtectedKey(const wchar_t* path, HKEY* phKey)
    {
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kKeySddl, SDDL_REVISION_1,
                                                                  &psd, nullptr))
            return static_cast<LSTATUS>(GetLastError());

        SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };
        DWORD disposition = 0;
        LSTATUS status = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, nullptr, 0,
                                         KEY_SET_VALUE | KEY_QUERY_VALUE | WRITE_DAC,
                                         &sa, phKey, &disposition);
        if (status == ERROR_SUCCESS && disposition == REG_OPENED_EXISTING_KEY)
        {
            status = RegSetKeySecurity(*phKey, DACL_SECURITY_INFORMATION, psd);
            if (status != ERROR_SUCCESS)
            {
                RegCloseKey(*phKey);
                *phKey = nullptr;
            }
        }

        LocalFree(psd);
        return status;
    }

    // Deletes one value and treats "was not there" as done.
    static bool DeleteValue(const wchar_t* path, const std::wstring& value)
    {
        HKEY hKey = nullptr;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &hKey);
        if (status == ERROR_FILE_NOT_FOUND)
            return true;
        if (status != ERROR_SUCCESS)
            return false;

        status = RegDeleteValueW(hKey, value.c_str());
        RegCloseKey(hKey);
        return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
    }

    // Writes a presence flag (REG_DWORD 1) under one of the index keys.
    static bool SetFlag(const wchar_t* path, const std::wstring& value)
    {
        HKEY hKey = nullptr;
        if (OpenProtectedKey(path, &hKey) != ERROR_SUCCESS)
            return false;
        DWORD one = 1;
        bool ok = RegSetValueExW(hKey, value.c_str(), 0, REG_DWORD,
                                 reinterpret_cast<const BYTE*>(&one), sizeof(one)) == ERROR_SUCCESS;
        RegCloseKey(hKey);
        return ok;
    }

    // Writes the RID index and, if the SID still resolves to a name, the name
    // index for one enrolled SID.
    static void WriteIndexes(const std::wstring& sid, bool& ridOk, bool& nameOk)
    {
        ridOk = nameOk = false;

        DWORD rid = 0;
        if (RidFromSidString(sid, rid))
            ridOk = SetFlag(kRidPath, std::to_wstring(rid));

        std::wstring name;
        if (NameFromSid(sid, name))
            nameOk = SetFlag(kNamePath, name);
    }

    bool StoreSecret(const std::wstring& sid, const std::string& base32Secret)
    {
        if (!IsSidString(sid))
            return false;

        std::vector<BYTE> blob;
        if (!Protect(base32Secret, blob))
            return false;

        // The indexes the LSA hot path reads come first. If they cannot be
        // written, nothing else is touched, so a re-enrollment that fails
        // leaves the old enrollment working. If the secret then fails, the
        // index entries stay behind: that only makes the LSA packages refuse
        // MORE (network logon of an account without a secret), never less,
        // and `enroll /remove` clears them.
        bool ridOk = false, nameOk = false;
        WriteIndexes(sid, ridOk, nameOk);
        if (!ridOk || !nameOk)
            return false;

        HKEY hKey = nullptr;
        LSTATUS status = OpenProtectedKey(kKeyPath, &hKey);
        if (status == ERROR_SUCCESS)
        {
            status = RegSetValueExW(hKey, sid.c_str(), 0, REG_BINARY,
                                    blob.data(), static_cast<DWORD>(blob.size()));
            RegCloseKey(hKey);
        }
        return status == ERROR_SUCCESS;
    }

    bool LoadSecretKey(const std::wstring& sid, std::vector<BYTE>& key)
    {
        key.clear();
        if (!IsSidString(sid))
            return false;

        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKeyPath, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
            return false;

        DWORD type = 0;
        DWORD cb = 0;
        std::vector<BYTE> blob;
        LSTATUS status = RegQueryValueExW(hKey, sid.c_str(), nullptr, &type, nullptr, &cb);
        if (status == ERROR_SUCCESS && type == REG_BINARY && cb > 0)
        {
            blob.resize(cb);
            status = RegQueryValueExW(hKey, sid.c_str(), nullptr, &type, blob.data(), &cb);
        }
        RegCloseKey(hKey);
        if (status != ERROR_SUCCESS || blob.empty())
            return false;

        std::string base32;
        if (!Unprotect(blob, base32))
            return false;

        bool ok = Base32Decode(base32, key);
        SecureZeroMemory(&base32[0], base32.size());

        // An empty or very short key would make the code predictable. Our
        // secrets have 20 bytes; anything under 16 counts as broken.
        if (!ok || key.size() < 16)
        {
            if (!key.empty())
                SecureZeroMemory(key.data(), key.size());
            key.clear();
            return false;
        }
        return true;
    }

    bool IsEnrolledByRid(DWORD rid)
    {
        if (rid == 0)
            return false;

        // A single registry read, like IsEnrolledByName below.
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRidPath, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
            return false;

        WCHAR value[16];
        swprintf_s(value, L"%lu", static_cast<unsigned long>(rid));
        LSTATUS status = RegQueryValueExW(hKey, value, nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(hKey);
        return status == ERROR_SUCCESS;
    }

    bool IsEnrolledByName(const std::wstring& user)
    {
        std::wstring name = NormalizeUser(user);
        if (name.empty())
            return false;

        // A single registry read. No DPAPI, no LookupAccount* - nothing that
        // re-enters LSA - so this is safe to call from inside lsass on the
        // logon path.
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kNamePath, 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS)
            return false;

        LSTATUS status = RegQueryValueExW(hKey, name.c_str(), nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(hKey);
        return status == ERROR_SUCCESS;
    }

    bool RemoveEnrollment(const std::wstring& user, const std::wstring& sid)
    {
        bool ok = true;

        // The name-keyed index first: it is the half that can still be found
        // when the account no longer exists. The RID entry of a deleted
        // account is harmless, the SAM never hands that RID out again.
        std::wstring typed = NormalizeUser(user);
        if (!typed.empty())
            ok = DeleteValue(kNamePath, typed) && ok;

        if (IsSidString(sid))
        {
            // StoreSecret keys the index by the name it got from NameFromSid,
            // not by whatever was typed. Those are normally the same, but
            // LookupAccountName accepts spellings the SAM does not store, so
            // remove the canonical one as well. Deleting a value twice is free.
            std::wstring canonical;
            if (NameFromSid(sid, canonical) && !canonical.empty() && canonical != typed)
                ok = DeleteValue(kNamePath, canonical) && ok;

            DWORD rid = 0;
            if (RidFromSidString(sid, rid))
                ok = DeleteValue(kRidPath, std::to_wstring(rid)) && ok;

            ok = DeleteValue(kKeyPath, sid) && ok;
            ok = DeleteValue(kStatePath, sid) && ok;
        }
        return ok;
    }

    bool QueryAnyEnrollment(bool& any)
    {
        any = false;
        HKEY hKey = nullptr;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKeyPath, 0, KEY_QUERY_VALUE, &hKey);
        if (status == ERROR_FILE_NOT_FOUND)
            return true;
        if (status != ERROR_SUCCESS)
            return false;

        DWORD values = 0;
        status = RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                                  &values, nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(hKey);
        if (status != ERROR_SUCCESS)
            return false;
        any = values > 0;
        return true;
    }

    bool PurgeAllEnrollments()
    {
        // HKLM\SOFTWARE\TheAdminCafe\2FA and everything below it, then the
        // vendor key if nothing else lives there.
        LSTATUS status = RegDeleteTreeW(HKEY_LOCAL_MACHINE, kKeyPath);
        if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
            return false;
        status = RegDeleteKeyW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\TheAdminCafe");
        // Not empty (someone else's data) or already gone: both fine.
        (void)status;
        return true;
    }

    int ReindexEnrollments()
    {
        HKEY hKey = nullptr;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kKeyPath, 0, KEY_QUERY_VALUE, &hKey);
        if (status == ERROR_FILE_NOT_FOUND)
            return 0;                           // nothing enrolled yet
        if (status != ERROR_SUCCESS)
            return -1;

        // Collect first, write afterwards: the index keys are subkeys of this
        // one, and enumerating while writing elsewhere is simpler to reason about.
        std::vector<std::wstring> sids;
        for (DWORD i = 0;; ++i)
        {
            WCHAR name[256];
            DWORD cch = ARRAYSIZE(name);
            DWORD type = 0;
            status = RegEnumValueW(hKey, i, name, &cch, nullptr, &type, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS)
                break;
            if (status == ERROR_MORE_DATA)
                continue;                       // not one of ours, SIDs are short
            if (status != ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return -1;
            }
            if (type == REG_BINARY && IsSidString(name))
                sids.emplace_back(name, cch);
        }
        RegCloseKey(hKey);

        // The RID index is what the sub-authentication filter reads, so a
        // failure there is an error. A missing name is not: the account may
        // have been deleted, and then there is no name to index.
        int count = 0;
        for (const std::wstring& sid : sids)
        {
            bool ridOk = false, nameOk = false;
            WriteIndexes(sid, ridOk, nameOk);
            if (!ridOk)
                return -1;
            ++count;
        }
        return count;
    }

    bool LoadState(const std::wstring& sid, UserState& state)
    {
        ZeroMemory(&state, sizeof(state));
        if (!IsSidString(sid))
            return false;

        HKEY hKey = nullptr;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStatePath, 0, KEY_QUERY_VALUE, &hKey);
        if (status == ERROR_FILE_NOT_FOUND)
            return true;                      // nobody has logged on yet
        if (status != ERROR_SUCCESS)
            return false;

        DWORD type = 0;
        DWORD cb = sizeof(state);
        status = RegQueryValueExW(hKey, sid.c_str(), nullptr, &type,
                                  reinterpret_cast<BYTE*>(&state), &cb);
        RegCloseKey(hKey);

        if (status == ERROR_FILE_NOT_FOUND)
        {
            ZeroMemory(&state, sizeof(state));
            return true;                      // this user has not logged on yet
        }
        // Anything else that is not exactly our structure is an error. The
        // caller fails closed, so a broken value cannot reset the counters.
        return status == ERROR_SUCCESS && type == REG_BINARY && cb == sizeof(state);
    }

    bool SaveState(const std::wstring& sid, const UserState& state)
    {
        if (!IsSidString(sid))
            return false;

        HKEY hKey = nullptr;
        LSTATUS status = OpenProtectedKey(kStatePath, &hKey);
        if (status == ERROR_SUCCESS)
        {
            status = RegSetValueExW(hKey, sid.c_str(), 0, REG_BINARY,
                                    reinterpret_cast<const BYTE*>(&state), sizeof(state));
            // No RegFlushKey: it can write out large parts of the hive and
            // blocks the logon until the disk is done, on every attempt. The
            // cost of leaving it out is narrow: a hard reset within seconds of
            // a logon can lose the last state write.
            RegCloseKey(hKey);
        }
        return status == ERROR_SUCCESS;
    }

    bool DeleteState(const std::wstring& sid)
    {
        if (!IsSidString(sid))
            return false;
        return DeleteValue(kStatePath, sid);
    }
}
