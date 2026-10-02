#include "subauth.h"
#include "store.h"
#include <string>

#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif

namespace
{
    void SaDebug(const std::wstring& text)
    {
        OutputDebugStringW((L"[Doppio-SubAuth] " + text + L"\n").c_str());
    }

    // Event log only for refusals. The filter sees every MSV1_0 logon it is
    // called for, so logging the approvals too would flood the Application log
    // from inside lsass.
    void SaEvent(WORD type, DWORD id, const std::wstring& text)
    {
        SaDebug(text);
        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text.c_str() };
            ReportEventW(h, type, 0, id, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
    }

    // The SAM account name, for the log only. Bounded like any other input.
    std::wstring SamName(const USER_ALL_INFORMATION* ua)
    {
        const UNICODE_STRING& us = ua->UserName;
        if (!us.Buffer || us.Length == 0 || us.Length > 512 || (us.Length % sizeof(WCHAR)) != 0)
            return L"?";
        return std::wstring(us.Buffer, us.Length / sizeof(WCHAR));
    }
}

// MSV1_0 calls this AFTER it has validated the logon. We only add a veto;
// password check, account restrictions and token stay with MSV1_0.
//
// The output parameters are left as MSV1_0 passed them in, except WhichFields
// (nothing to write back to the SAM) and Authoritative on a refusal. In
// particular LogoffTime and KickoffTime are NOT overwritten: they carry the
// account's logon hours, and a filter has no business extending them.
//
// IMPORTANT: we read ONLY the RID and the account name. We never touch the
// password hashes in UserAll or the challenge-response in LogonInformation.
// Reading and keeping that credential material is exactly the theft pattern
// this project refuses to build - the decision never needs it.
NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(
    NETLOGON_LOGON_INFO_CLASS LogonLevel,
    PVOID /*LogonInformation*/,
    ULONG /*Flags*/,
    PUSER_ALL_INFORMATION UserAll,
    PULONG WhichFields,
    PULONG /*UserFlags*/,
    PBOOLEAN Authoritative,
    PLARGE_INTEGER /*LogoffTime*/,
    PLARGE_INTEGER /*KickoffTime*/)
{
    if (WhichFields)
        *WhichFields = 0;

    // No SAM record, no decision: MSV1_0 has already validated the logon, so
    // "no objection" here does not let anything through that MSV1_0 refused.
    if (!UserAll)
        return STATUS_SUCCESS;

    const bool isNetwork = (LogonLevel == NetlogonNetworkInformation ||
                            LogonLevel == NetlogonNetworkTransitiveInformation);
    const ULONG rid = UserAll->UserId;

    // A single registry read - no DPAPI, no LSA name/SID lookup - so nothing
    // here re-enters LSA from inside MSV1_0.
    const bool enrolled = isNetwork && tac::IsEnrolledByRid(rid);

    if (enrolled)
    {
        if (Authoritative)
            *Authoritative = TRUE;              // do not retry elsewhere
        SaEvent(EVENTLOG_WARNING_TYPE, 210,
                L"Refused a network logon for enrolled account '" + SamName(UserAll) +
                L"' (RID " + std::to_wstring(rid) + L"). No second factor on this path.");
        return STATUS_ACCOUNT_RESTRICTION;
    }

    SaDebug(L"No objection to a " + std::wstring(isNetwork ? L"network" : L"non-network") +
            L" logon for '" + SamName(UserAll) + L"' (RID " + std::to_wstring(rid) + L").");
    return STATUS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
