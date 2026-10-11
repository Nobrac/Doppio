#include "subauth_filter.h"
#include "store.h"

#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif

// Everything in this file runs inside lsass.exe, on MSV1_0's logon path. The
// rules, three of them learned the hard way in Part 3 (Ristretto):
//
//  * No heap: fixed stack buffers, no std::wstring, so no std::bad_alloc.
//  * No CRT on the decision path. swprintf_s calls the invalid-parameter
//    handler on overflow, and the default handler ends the process - here
//    lsass, which is a bugcheck. Log lines are built with Buf, which cuts
//    instead.
//  * SEH, not C++ try/catch. With /EHsc a catch (...) does not catch an
//    access violation, and a bad pointer from the caller is the failure that
//    actually matters here. The decision runs behind one __except.
//  * A failed enrollment read refuses the logon. In a filter whose only job
//    is the veto, "could not tell" must never come out as "not enrolled".

namespace
{
    // ---- bounded, CRT-free string building ---------------------------
    class Buf
    {
    public:
        Buf(WCHAR* p, SIZE_T cap) : p_(p), cap_(cap), n_(0)
        {
            if (cap_) p_[0] = L'\0';
        }

        void Str(const WCHAR* s)
        {
            if (!s) return;
            while (*s && n_ + 1 < cap_) p_[n_++] = *s++;
            if (cap_) p_[n_] = L'\0';
        }

        void U64(ULONGLONG v)
        {
            WCHAR t[21];
            int i = 0;
            do { t[i++] = (WCHAR)(L'0' + (ULONG)(v % 10)); v /= 10; } while (v && i < 20);
            while (i > 0 && n_ + 1 < cap_) p_[n_++] = t[--i];
            if (cap_) p_[n_] = L'\0';
        }

    private:
        WCHAR* p_;
        SIZE_T cap_;
        SIZE_T n_;
    };

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

    enum class Verdict { NoObjection, Refused, Unreadable };

    // Debug output for every decision; the event log only for refusals. The
    // filter sees every MSV1_0 logon it is called for, so logging approvals to
    // the Application log would flood it from inside lsass.
    void Report(Verdict v, ULONG rid, const WCHAR* name, bool isNetwork)
    {
        WCHAR text[256];
        Buf b(text, ARRAYSIZE(text));
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

        WCHAR debug[288];
        Buf d(debug, ARRAYSIZE(debug));
        d.Str(L"[Doppio-SubAuth] ");
        d.Str(text);
        d.Str(L"\n");
        OutputDebugStringW(debug);

        if (v == Verdict::NoObjection)
            return;
        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text };
            ReportEventW(h, EVENTLOG_WARNING_TYPE, 0, 210, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
    }

    // Which exceptions the __except below swallows. A stack overflow is not
    // ours to survive: the guard page is gone by the time the filter runs.
    // Everything else here means a bad pointer from the caller, and on that
    // one a dead lsass is the worse outcome, so it is caught.
    LONG DecisionFilter(DWORD code)
    {
        switch (code)
        {
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return EXCEPTION_CONTINUE_SEARCH;
        default:
            return EXCEPTION_EXECUTE_HANDLER;
        }
    }

    // The decision. Split out of the export so the __try frame there holds
    // nothing that needs unwinding (MSVC error C2712 otherwise).
    NTSTATUS Decide(const USER_ALL_INFORMATION* ua, bool isNetwork)
    {
        // No SAM record, no decision: MSV1_0 has already validated the logon,
        // so "no objection" does not let anything through that MSV1_0 refused.
        if (!ua)
            return STATUS_SUCCESS;

        const ULONG rid = ua->UserId;
        WCHAR name[129];
        SamName(ua, name);

        if (!isNetwork)
        {
            Report(Verdict::NoObjection, rid, name, false);
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
            return STATUS_ACCOUNT_RESTRICTION;

        case tac::Enrollment::Yes:
        default:
            Report(Verdict::Refused, rid, name, true);
            return STATUS_ACCOUNT_RESTRICTION;
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

    NTSTATUS result;

    // An access violation in here would take lsass down with it. Catching it
    // is the lesser evil: refuse the path this filter exists for, and stay out
    // of the way of everything else. Nothing below allocates, so there is no
    // state to unwind.
    __try
    {
        result = Decide(UserAll, isNetwork);
    }
    __except (DecisionFilter(GetExceptionCode()))
    {
        OutputDebugStringW(L"[Doppio-SubAuth] Exception while deciding a logon - "
                           L"refused if it was a network logon (fail closed).\n");
        result = isNetwork ? STATUS_ACCOUNT_RESTRICTION : STATUS_SUCCESS;
    }

    if (result != STATUS_SUCCESS && Authoritative)
        *Authoritative = TRUE;              // the refusal is final
    return result;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
