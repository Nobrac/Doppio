#include "statelock.h"
#include <sddl.h>
#include <string>

#pragma comment(lib, "advapi32.lib")

namespace tac
{
    // Full path of "state.lock" in the folder of the module this code is
    // linked into (TacProvider.dll in LogonUI, enroll.exe on the console).
    static bool LockFilePath(std::wstring& path)
    {
        HMODULE self = nullptr;
        if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                reinterpret_cast<LPCWSTR>(&LockFilePath), &self))
            return false;

        WCHAR buf[MAX_PATH];
        DWORD cch = GetModuleFileNameW(self, buf, ARRAYSIZE(buf));
        if (cch == 0 || cch >= ARRAYSIZE(buf))
            return false;

        path.assign(buf, cch);
        size_t slash = path.find_last_of(L'\\');
        if (slash == std::wstring::npos)
            return false;
        path.erase(slash + 1);
        path += L"state.lock";
        return true;
    }

    StateLock::StateLock(DWORD timeoutMs)
        : _h(INVALID_HANDLE_VALUE)
    {
        std::wstring path;
        if (!LockFilePath(path))
            return;

        // SYSTEM and Administrators only, not inherited from the folder.
        PSECURITY_DESCRIPTOR psd = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                L"D:P(A;;FA;;;SY)(A;;FA;;;BA)", SDDL_REVISION_1, &psd, nullptr))
            return;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), psd, FALSE };

        const ULONGLONG deadline = GetTickCount64() + timeoutMs;
        for (;;)
        {
            // Share mode 0: while we hold the handle, every other open fails
            // with ERROR_SHARING_VIOLATION. That is the whole lock.
            _h = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, 0, &sa,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (_h != INVALID_HANDLE_VALUE)
                break;
            if (GetLastError() != ERROR_SHARING_VIOLATION || GetTickCount64() >= deadline)
                break;
            Sleep(20);
        }

        LocalFree(psd);
    }

    StateLock::~StateLock()
    {
        if (_h != INVALID_HANDLE_VALUE)
            CloseHandle(_h);
    }
}
