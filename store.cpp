#include "store.h"
#include "totp.h"
#include <wincrypt.h>
#include <sddl.h>
#include <cwctype>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace tac
{
    static const wchar_t kKeyPath[]   = L"SOFTWARE\\TheAdminCafe\\2FA";
    static const wchar_t kStatePath[] = L"SOFTWARE\\TheAdminCafe\\2FA\\State";

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
        // No UI may ever appear on the secure desktop.
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

        // The scope is stored in the blob, so no LOCAL_MACHINE flag here.
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

    bool StoreSecret(const std::wstring& sid, const std::string& base32Secret)
    {
        if (!IsSidString(sid))
            return false;

        std::vector<BYTE> blob;
        if (!Protect(base32Secret, blob))
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
            RegFlushKey(hKey);   // survive a hard reset right after the logon
            RegCloseKey(hKey);
        }
        return status == ERROR_SUCCESS;
    }

    bool DeleteState(const std::wstring& sid)
    {
        if (!IsSidString(sid))
            return false;

        HKEY hKey = nullptr;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, kStatePath, 0, KEY_SET_VALUE, &hKey);
        if (status == ERROR_FILE_NOT_FOUND)
            return true;
        if (status != ERROR_SUCCESS)
            return false;

        status = RegDeleteValueW(hKey, sid.c_str());
        RegCloseKey(hKey);
        return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
    }
}
