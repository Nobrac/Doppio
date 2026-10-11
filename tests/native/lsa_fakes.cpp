// In-memory replacements for the handful of Windows APIs the lsass code calls.
#include "lsa_fakes.h"
#include <cstdlib>
#include <cwctype>

namespace fake
{
    std::map<std::wstring, std::set<std::wstring>> keys;

    LSTATUS openStatus   = ERROR_SUCCESS;
    LSTATUS queryStatus  = ERROR_SUCCESS;
    bool    throwOnOpen  = false;
    bool    failLcMap    = false;
    int     allocBudget  = -1;

    std::vector<std::wstring> debug;
    std::vector<DWORD>        events;
    int opened = 0, closed = 0;
    int lsaAllocs = 0, lsaFrees = 0;

    // Open handles: index + 1 -> key path.
    static std::vector<std::wstring> handles;

    static PVOID NTAPI Alloc(ULONG cb)
    {
        if (allocBudget == 0)
            return nullptr;
        if (allocBudget > 0)
            --allocBudget;
        ++lsaAllocs;
        return std::calloc(1, cb ? cb : 1);
    }

    static VOID NTAPI Free(PVOID p)
    {
        if (p)
            ++lsaFrees;
        std::free(p);
    }

    LSA_DISPATCH_TABLE lsa = { &Alloc, &Free };

    void Reset()
    {
        keys.clear();
        openStatus   = ERROR_SUCCESS;
        queryStatus  = ERROR_SUCCESS;
        throwOnOpen  = false;
        failLcMap    = false;
        allocBudget  = -1;
        debug.clear();
        events.clear();
        handles.clear();
        opened = closed = 0;
        lsaAllocs = lsaFrees = 0;
    }

    bool DebugContains(const wchar_t* text)
    {
        for (const std::wstring& line : debug)
            if (line.find(text) != std::wstring::npos)
                return true;
        return false;
    }
}

int LCMapStringW(LCID, DWORD, LPCWSTR src, int cchSrc, LPWSTR dst, int cchDst)
{
    if (fake::failLcMap || cchSrc <= 0 || cchSrc > cchDst)
        return 0;
    for (int i = 0; i < cchSrc; ++i)
        dst[i] = static_cast<WCHAR>(std::towlower(static_cast<wint_t>(src[i])));
    return cchSrc;
}

LSTATUS RegOpenKeyExW(HKEY root, LPCWSTR path, DWORD, REGSAM, PHKEY out)
{
    *out = nullptr;
    if (fake::throwOnOpen)
        throw 1;
    if (root != HKEY_LOCAL_MACHINE || !path)
        return ERROR_FILE_NOT_FOUND;
    if (fake::keys.find(path) == fake::keys.end())
        return ERROR_FILE_NOT_FOUND;
    if (fake::openStatus != ERROR_SUCCESS)
        return fake::openStatus;

    fake::handles.push_back(path);
    ++fake::opened;
    *out = reinterpret_cast<HKEY>(static_cast<ULONG_PTR>(fake::handles.size()));
    return ERROR_SUCCESS;
}

LSTATUS RegQueryValueExW(HKEY h, LPCWSTR value, LPDWORD, LPDWORD, LPBYTE, LPDWORD)
{
    if (fake::queryStatus != ERROR_SUCCESS)
        return fake::queryStatus;

    const size_t index = static_cast<size_t>(reinterpret_cast<ULONG_PTR>(h));
    if (index == 0 || index > fake::handles.size())
        return ERROR_FILE_NOT_FOUND;
    const auto& values = fake::keys[fake::handles[index - 1]];
    return values.count(value) ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
}

LSTATUS RegCloseKey(HKEY)
{
    ++fake::closed;
    return ERROR_SUCCESS;
}

void OutputDebugStringW(LPCWSTR text)
{
    fake::debug.emplace_back(text ? text : L"");
}

HANDLE RegisterEventSourceW(LPCWSTR, LPCWSTR)
{
    return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(1));
}

BOOL ReportEventW(HANDLE, WORD, WORD, DWORD id, PSID, WORD, DWORD, LPCWSTR*, LPVOID)
{
    fake::events.push_back(id);
    return TRUE;
}

BOOL DeregisterEventSource(HANDLE)
{
    return TRUE;
}

BOOL DisableThreadLibraryCalls(HMODULE)
{
    return TRUE;
}
