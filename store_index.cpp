// The enrollment-index reads that run INSIDE lsass: the sub-authentication
// filter and the authentication package link this file and nothing else from
// the store. No DPAPI, no TOTP, no name or SID lookup, no heap and no CRT of
// our own - see lsasafe.h for why each of those matters in lsass.
//
// Everything that writes the indexes, or needs DPAPI, lives in store.cpp and
// only ever runs in LogonUI or enroll.exe.

#include "store.h"
#include "storekeys.h"

#pragma comment(lib, "advapi32.lib")

namespace tac
{
    bool NormalizeUserInto(const WCHAR* user, SIZE_T cch, WCHAR* out, SIZE_T outCap)
    {
        if (!user || !out || outCap == 0)
            return false;
        out[0] = L'\0';

        // Stop at an embedded NUL: nothing after it belongs to the name.
        SIZE_T len = 0;
        while (len < cch && user[len] != L'\0')
            ++len;

        // Keep only what follows the last backslash.
        SIZE_T start = 0;
        for (SIZE_T i = 0; i < len; ++i)
            if (user[i] == L'\\')
                start = i + 1;

        const SIZE_T bare = len - start;
        if (bare == 0 || bare >= outCap)
            return false;

        // LOCALE_INVARIANT, so "JÖRG" and "jörg" fold the same way on every
        // machine. Plain towlower only ever folded ASCII, which made the name
        // index miss non-ASCII names.
        const int written = LCMapStringW(LOCALE_INVARIANT, LCMAP_LOWERCASE,
                                         user + start, static_cast<int>(bare),
                                         out, static_cast<int>(outCap - 1));
        if (written > 0 && static_cast<SIZE_T>(written) < outCap)
        {
            out[written] = L'\0';
            return true;
        }

        // NLS unavailable or the mapping did not fit: fold ASCII only, which
        // is what every name used to get.
        for (SIZE_T i = 0; i < bare; ++i)
        {
            const WCHAR c = user[start + i];
            out[i] = (c >= L'A' && c <= L'Z') ? static_cast<WCHAR>(c - L'A' + L'a') : c;
        }
        out[bare] = L'\0';
        return true;
    }

    // The RID as the decimal value name of the Rids index, without the CRT.
    // This runs inside lsass, where swprintf_s on an overflow would end the
    // process. A DWORD has at most 10 digits, so out[12] always fits.
    static void RidToValueName(DWORD rid, WCHAR (&out)[12])
    {
        WCHAR digits[10];
        int n = 0;
        do
        {
            digits[n++] = static_cast<WCHAR>(L'0' + rid % 10);
            rid /= 10;
        } while (rid != 0 && n < 10);

        int i = 0;
        while (n > 0)
            out[i++] = digits[--n];
        out[i] = L'\0';                   // i <= 10, so this is in bounds
    }

    // One registry read of an index key, with the three outcomes a vetoing
    // caller needs.
    static Enrollment QueryIndex(const wchar_t* path, const WCHAR* value)
    {
        HKEY hKey = nullptr;
        LSTATUS status = RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_QUERY_VALUE, &hKey);
        if (status == ERROR_FILE_NOT_FOUND)
            return Enrollment::No;          // no index on this machine at all
        if (status != ERROR_SUCCESS)
            return Enrollment::Unknown;

        status = RegQueryValueExW(hKey, value, nullptr, nullptr, nullptr, nullptr);
        RegCloseKey(hKey);

        if (status == ERROR_SUCCESS)
            return Enrollment::Yes;
        if (status == ERROR_FILE_NOT_FOUND)
            return Enrollment::No;
        // Only a value that is really not there counts as "not enrolled". Any
        // other failure is Unknown: a filter that read it as "not enrolled"
        // would wave an enrolled account through on one unexpected error.
        return Enrollment::Unknown;
    }

    Enrollment EnrollmentByRid(DWORD rid)
    {
        if (rid == 0)
            return Enrollment::No;

        WCHAR value[12];
        RidToValueName(rid, value);
        return QueryIndex(keys::kRids, value);
    }

    bool IsEnrolledByRid(DWORD rid)
    {
        return EnrollmentByRid(rid) == Enrollment::Yes;
    }

    Enrollment EnrollmentByName(const WCHAR* name, SIZE_T cch)
    {
        WCHAR normalized[keys::kMaxNameCch];
        if (!NormalizeUserInto(name, cch, normalized, ARRAYSIZE(normalized)))
            return Enrollment::Unknown;     // unusable name: never claim "No"

        return QueryIndex(keys::kNames, normalized);
    }
}
