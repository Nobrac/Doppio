#pragma once
#include <windows.h>
#include <string>

namespace tac
{
    // Event IDs in the Application log, source "TheAdminCafe 2FA".
    enum : DWORD
    {
        EVT_CODE_OK       = 100,
        EVT_CODE_WRONG    = 101,
        EVT_CODE_REPLAYED = 102,
        EVT_LOCKED_OUT    = 103,   // attempt while the account was locked
        EVT_LOCK_STARTED  = 104,   // this attempt locked the account
        EVT_NOT_ENROLLED  = 105,
        EVT_ERROR         = 106,
    };

    // Writes one line of text. Never throws, never shows UI. If the event log
    // is not reachable, the event is lost and the logon goes on.
    void LogEvent(WORD type, DWORD id, const std::wstring& text);

    // "console, session 1" or "remote from 192.168.1.50, session 3".
    std::wstring DescribeSession();
}
