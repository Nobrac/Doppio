#include "subauth_filter.h"
#include "lsasafe.h"
#include "store.h"

#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
// The documentation of Msv1_0SubAuthenticationFilter lists the values this
// function "must return". STATUS_ACCOUNT_RESTRICTION, which this filter used
// to veto with, is not among them; STATUS_INVALID_WORKSTATION is, and it says
// what we mean: this account may not log on over this path.
#ifndef STATUS_INVALID_WORKSTATION
#define STATUS_INVALID_WORKSTATION ((NTSTATUS)0xC0000070L)
#endif

#ifndef MSV1_0_PASSTHRU
#define MSV1_0_PASSTHRU            0x01
#endif

// Everything in this file runs inside lsass.exe, on MSV1_0's logon path, under
// the rules in lsasafe.h: no heap and no CRT of our own on the decision path,
// and SEH rather than C++ try/catch. On top of those:
//
//  * A failed enrollment read refuses the logon. In a filter whose only job
//    is the veto, "could not tell" must never come out as "not enrolled".

namespace
{
    // The SAM account name, for the log only. The decision runs on the RID.
    void SamName(const USER_ALL_INFORMATION* ua, WCHAR (&out)[129])
    {
        out[0] = L'?';
        out[1] = L'\0';
        if (!ua) return;

        const UNICODE_STRING& us = ua->UserName;
        if (!us.Buffer || us.Length == 0 || (us.Length % sizeof(WCHAR)) != 0)
            return;

        SIZE_T cch = us.Length / sizeof(WCHAR);
        if (cch > 128) cch = 128;
        for (SIZE_T i = 0; i < cch; ++i)
        {
            WCHAR c = us.Buffer[i];
            if (c == L'\0') { cch = i; break; }
            // Keep control characters out of the log line.
            out[i] = (c < 0x20) ? L'.' : c;
        }
        out[cch] = L'\0';
    }

    enum class Verdict { NoObjection, Refused, Unreadable, NotOurs, NoRecord };

    // Debug output for every decision; the event log only for refusals. The
    // filter sees every MSV1_0 logon it is called for, so logging approvals to
    // the Application log would flood it from inside lsass.
    void Report(Verdict v, ULONG rid, const WCHAR* name, bool isNetwork)
    {
        WCHAR text[256];
        tac::Buf b(text, ARRAYSIZE(text));
        switch (v)
        {
        case Verdict::Refused:
            b.Str(L"Refused a network logon for enrolled account '");
            b.Str(name);
            b.Str(L"' (RID ");
            b.U64(rid);
            b.Str(L"). No second factor on this path.");
            break;
        case Verdict::Unreadable:
            b.Str(L"Refused a network logon for '");
            b.Str(name);
            b.Str(L"' (RID ");
            b.U64(rid);
            b.Str(L"): the enrollment index could not be read.");
            break;
        case Verdict::NoRecord:
            b.Str(L"Refused a network logon: MSV1_0 passed no SAM record, so the "
                  L"account could not be identified.");
            break;
        case Verdict::NotOurs:
            b.Str(L"No objection: pass-through logon for '");
            b.Str(name);
            b.Str(L"' (RID ");
            b.U64(rid);
            b.Str(L"), the account does not live on this machine.");
            break;
        default:
            b.Str(L"No objection to a ");
            b.Str(isNetwork ? L"network" : L"non-network");
            b.Str(L" logon for '");
            b.Str(name);
            b.Str(L"' (RID ");
            b.U64(rid);
            b.Str(L").");
            break;
        }

        WCHAR debug[352];
        tac::Buf d(debug, ARRAYSIZE(debug));
        d.Str(L"[Doppio-SubAuth] ");
        d.Str(text);
        d.Str(L"\n");
        OutputDebugStringW(debug);

        if (v == Verdict::NoObjection || v == Verdict::NotOurs)
            return;
        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text };
            ReportEventW(h, EVENTLOG_WARNING_TYPE, 0, 210, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
    }

    // The logon hours MSV1_0 passed in, so the VM test can settle what the
    // filter is actually handed in LogoffTime and KickoffTime. The
    // documentation calls both [out] and does not say what they hold on the
    // way in; this filter leaves them alone either way (see the export below),
    // and the debugger line is how you check that assumption.
    void ReportTimes(const LARGE_INTEGER* logoff, const LARGE_INTEGER* kickoff)
    {
        WCHAR text[160];
        tac::Buf b(text, ARRAYSIZE(text));
        b.Str(L"[Doppio-SubAuth] incoming LogoffTime=");
        if (logoff) b.U64(static_cast<ULONGLONG>(logoff->QuadPart)); else b.Str(L"(null)");
        b.Str(L" KickoffTime=");
        if (kickoff) b.U64(static_cast<ULONGLONG>(kickoff->QuadPart)); else b.Str(L"(null)");
        b.Str(L"\n");
        OutputDebugStringW(text);
    }

    // The decision. Split out of the export so the __try frame there holds
    // nothing that needs unwinding (MSVC error C2712 otherwise).
    NTSTATUS Decide(const USER_ALL_INFORMATION* ua, bool isNetwork, bool passthru)
    {
        // No SAM record: without a RID there is no telling whether the account
        // is enrolled, and "could not tell" must not come out as "no objection"
        // on the one path this filter exists for. Everything else keeps its
        // usual answer - non-network logons belong to the credential provider,
        // pass-through logons to another machine.
        if (!ua)
        {
            if (!isNetwork || passthru)
                return STATUS_SUCCESS;
            Report(Verdict::NoRecord, 0, L"?", true);
            return STATUS_INVALID_WORKSTATION;
        }

        const ULONG rid = ua->UserId;
        WCHAR name[129];
        SamName(ua, name);

        if (!isNetwork)
        {
            Report(Verdict::NoObjection, rid, name, false);
            return STATUS_SUCCESS;
        }

        // MSV1_0_PASSTHRU means "the user is not connecting to this machine".
        // Our index only knows local accounts, and a RID from somewhere else
        // could collide with a local one, so we have nothing to say.
        if (passthru)
        {
            Report(Verdict::NotOurs, rid, name, true);
            return STATUS_SUCCESS;
        }

        // A single registry read - no DPAPI, no LSA name/SID lookup - so
        // nothing here re-enters LSA from inside MSV1_0.
        switch (tac::EnrollmentByRid(rid))
        {
        case tac::Enrollment::No:
            Report(Verdict::NoObjection, rid, name, true);
            return STATUS_SUCCESS;

        case tac::Enrollment::Unknown:
            // The index is there but this read failed. Do not guess "not
            // enrolled" - that is the one wrong answer that lets an enrolled
            // account through.
            Report(Verdict::Unreadable, rid, name, true);
            return STATUS_INVALID_WORKSTATION;

        case tac::Enrollment::Yes:
        default:
            Report(Verdict::Refused, rid, name, true);
            return STATUS_INVALID_WORKSTATION;
        }
    }
}

// MSV1_0 calls this AFTER it has validated the logon. We only add a veto;
// password check, account restrictions and token stay with MSV1_0.
//
// The documentation calls WhichFields, UserFlags, Authoritative, LogoffTime and
// KickoffTime [out], so we write the three we can answer for:
//
//   * WhichFields = 0: nothing to write back to the SAM.
//   * UserFlags   = 0: we claim neither LOGON_GUEST nor LOGON_NOENCRYPTION.
//   * Authoritative = TRUE: the documentation says this "should return valid
//     information regardless of the return value", and our answer is final on
//     every path - there is no other domain controller that would decide
//     differently about a local account.
//
// LogoffTime and KickoffTime are deliberately NOT written: they carry the
// account's logon hours, and a filter has no business extending them. What
// MSV1_0 hands us there is undocumented, so every call logs the incoming
// values for the VM test (ReportTimes above).
//
// IMPORTANT: we read ONLY the RID and the account name. We never touch the
// password hashes in UserAll or the challenge-response in LogonInformation.
// Reading and keeping that credential material is exactly the theft pattern
// this project refuses to build - the decision never needs it.
NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(
    NETLOGON_LOGON_INFO_CLASS LogonLevel,
    PVOID /*LogonInformation*/,
    ULONG Flags,
    PUSER_ALL_INFORMATION UserAll,
    PULONG WhichFields,
    PULONG UserFlags,
    PBOOLEAN Authoritative,
    PLARGE_INTEGER LogoffTime,
    PLARGE_INTEGER KickoffTime)
{
    if (WhichFields)
        *WhichFields = 0;
    if (UserFlags)
        *UserFlags = 0;
    if (Authoritative)
        *Authoritative = TRUE;

    const bool isNetwork = (LogonLevel == NetlogonNetworkInformation ||
                            LogonLevel == NetlogonNetworkTransitiveInformation);
    const bool passthru  = (Flags & MSV1_0_PASSTHRU) != 0;

    ReportTimes(LogoffTime, KickoffTime);

    NTSTATUS result;

    // An access violation in here would take lsass down with it. Catching it
    // is the lesser evil: refuse the path this filter exists for, and stay out
    // of the way of everything else. Nothing below allocates, so there is no
    // state to unwind.
    __try
    {
        result = Decide(UserAll, isNetwork, passthru);
    }
    __except (tac::LsaDecisionExceptionFilter(GetExceptionCode()))
    {
        OutputDebugStringW(L"[Doppio-SubAuth] Exception while deciding a logon - "
                           L"refused if it was a network logon (fail closed).\n");
        result = (isNetwork && !passthru) ? STATUS_INVALID_WORKSTATION : STATUS_SUCCESS;
    }

    return result;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
