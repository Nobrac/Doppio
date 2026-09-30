#include "eventlog.h"
#include <wtsapi32.h>
#include <cstdio>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "wtsapi32.lib")

namespace tac
{
    static const wchar_t kSource[] = L"TheAdminCafe 2FA";

    void LogEvent(WORD type, DWORD id, const std::wstring& text)
    {
        HANDLE hLog = RegisterEventSourceW(nullptr, kSource);
        if (!hLog)
            return;

        LPCWSTR strings[1] = { text.c_str() };
        ReportEventW(hLog, type, 0, id, nullptr, 1, 0, strings, nullptr);
        DeregisterEventSource(hLog);
    }

    std::wstring DescribeSession()
    {
        DWORD sessionId = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

        wchar_t buf[96];
        if (!GetSystemMetrics(SM_REMOTESESSION))
        {
            swprintf_s(buf, L"console, session %lu", sessionId);
            return buf;
        }

        // For RDP, add the client address. LogonUI runs in the session of the
        // connection, so WTS_CURRENT_SESSION is the right one.
        std::wstring from = L"unknown address";
        WTS_CLIENT_ADDRESS* addr = nullptr;
        DWORD cb = 0;
        if (WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
                                        WTSClientAddress, reinterpret_cast<LPWSTR*>(&addr), &cb) &&
            addr && cb >= sizeof(*addr))
        {
            if (addr->AddressFamily == AF_INET)
            {
                // For IPv4 the address starts at offset 2 of the byte array.
                wchar_t ip[16];
                swprintf_s(ip, L"%u.%u.%u.%u", addr->Address[2], addr->Address[3],
                           addr->Address[4], addr->Address[5]);
                from = ip;
            }
            else
            {
                from = L"non-IPv4 address";
            }
        }
        if (addr)
            WTSFreeMemory(addr);

        swprintf_s(buf, L"remote from %s, session %lu", from.c_str(), sessionId);
        return buf;
    }
}
