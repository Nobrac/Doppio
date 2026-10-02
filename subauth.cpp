#include "subauth_filter.h"
#include "store.h"
#include <cstdio>

#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif

// Everything in this file runs inside lsass.exe, on MSV1_0's logon path. It is
// written to allocate nothing on the heap: fixed stack buffers, no std::wstring.
// No allocation means no std::bad_alloc, and the export still has a catch-all
// in case a later edit adds one. A C++ exception that reaches LSA would take
// lsass, and with it the whole machine, down.

namespace
{
    // The SAM account name, for the log only. Bounded like any other input.
    void SamName(const USER_ALL_INFORMATION* ua, WCHAR (&out)[129])
    {
        out[0] = L'?';
        out[1] = L'\0';
        const UNICODE_STRING& us = ua->UserName;
        if (!us.Buffer || us.Length == 0 || (us.Length % sizeof(WCHAR)) != 0)
            return;
        size_t cch = us.Length / sizeof(WCHAR);
        if (cch > 128)
            cch = 128;
        memcpy(out, us.Buffer, cch * sizeof(WCHAR));
        out[cch] = L'\0';
    }

    // Debug output for every decision; the event log only for refusals. The
    // filter sees every MSV1_0 logon it is called for, so logging approvals to
    // the Application log would flood it from inside lsass.
    void Report(bool refused, ULONG rid, const WCHAR* name, bool isNetwork)
    {
        WCHAR text[256];
        if (refused)
            swprintf_s(text, L"Refused a network logon for enrolled account '%s' (RID %lu). "
                             L"No second factor on this path.", name, rid);
        else
            swprintf_s(text, L"No objection to a %s logon for '%s' (RID %lu).",
                       isNetwork ? L"network" : L"non-network", name, rid);

        WCHAR debug[288];
        swprintf_s(debug, L"[Doppio-SubAuth] %s\n", text);
        OutputDebugStringW(debug);

        if (!refused)
            return;
        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text };
            ReportEventW(h, EVENTLOG_WARNING_TYPE, 0, 210, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
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

    const bool isNetwork = (LogonLevel == NetlogonNetworkInformation ||
                            LogonLevel == NetlogonNetworkTransitiveInformation);

    try
    {
        // No SAM record, no decision: MSV1_0 has already validated the logon,
        // so "no objection" does not let anything through that MSV1_0 refused.
        if (!UserAll)
            return STATUS_SUCCESS;

        const ULONG rid = UserAll->UserId;

        // A single registry read - no DPAPI, no LSA name/SID lookup - so
        // nothing here re-enters LSA from inside MSV1_0.
        const bool refuse = isNetwork && tac::IsEnrolledByRid(rid);

        WCHAR name[129];
        SamName(UserAll, name);
        Report(refuse, rid, name, isNetwork);

        if (refuse)
        {
            if (Authoritative)
                *Authoritative = TRUE;          // do not retry elsewhere
            return STATUS_ACCOUNT_RESTRICTION;
        }
        return STATUS_SUCCESS;
    }
    catch (...)
    {
        // Should be unreachable (nothing above allocates). If it ever happens:
        // fail closed for the path this filter exists for, and stay out of the
        // way of everything else.
        if (isNetwork)
        {
            if (Authoritative)
                *Authoritative = TRUE;
            return STATUS_ACCOUNT_RESTRICTION;
        }
        return STATUS_SUCCESS;
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
