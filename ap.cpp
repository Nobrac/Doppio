#include "ap.h"
#include "lsasafe.h"
#include "store.h"

#pragma comment(lib, "advapi32.lib")

// NTSTATUS values we return. They live in ntstatus.h, which clashes with
// windows.h, so we define the handful we need. Every one of these is listed in
// the documentation of LSA_AP_LOGON_USER_EX2 as a value this callback may
// return - STATUS_NOT_IMPLEMENTED, which this package used to decline with,
// is not.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)  // "account not allowed to log on here/now"
#endif
#ifndef STATUS_INVALID_LOGON_TYPE
#define STATUS_INVALID_LOGON_TYPE  ((NTSTATUS)0xC000010BL)
#endif
#ifndef STATUS_INVALID_WORKSTATION
#define STATUS_INVALID_WORKSTATION ((NTSTATUS)0xC0000070L)
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED     ((NTSTATUS)0xC0000002L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER   ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_NO_MEMORY
#define STATUS_NO_MEMORY           ((NTSTATUS)0xC0000017L)
#endif

// Every export below runs inside lsass.exe, so the rules from lsasafe.h apply:
// no heap of our own and no CRT on the logon path, and SEH rather than C++
// try/catch, because under /EHsc a catch (...) does not catch the access
// violation a bad pointer from the caller would cause. The only allocations
// here come from the LSA heap, through the dispatch table, because LSA asks
// for the account name that way and frees it itself.

// Kerberos message types we recognise in a submit buffer.
#ifndef KerbInteractiveLogon
#define KerbInteractiveLogon        2
#endif
#ifndef KerbWorkstationUnlockLogon
#define KerbWorkstationUnlockLogon  7
#endif

namespace
{
    PLSA_DISPATCH_TABLE g_lsa = nullptr;
    ULONG               g_packageId = 0;

    // UNLEN + 1.
    const SIZE_T kApNameCch = 257;

    // Logging from inside lsass. OutputDebugStringW is the channel you
    // actually read under a kernel debugger. ReportEvent is best-effort on top,
    // guarded so a logging failure can never affect a logon. We never log a
    // password or a code, only metadata.
    void ApLog(WORD type, DWORD id, const WCHAR* text)
    {
        WCHAR debug[320];
        tac::Buf d(debug, ARRAYSIZE(debug));
        d.Str(L"[Doppio-AP] ");
        d.Str(text);
        d.Str(L"\n");
        OutputDebugStringW(debug);

        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text };
            ReportEventW(h, type, 0, id, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
    }

    bool IsNonInteractive(SECURITY_LOGON_TYPE t)
    {
        switch (t)
        {
        case Network:            // 3
        case Batch:              // 4
        case Service:            // 5
        case NetworkCleartext:   // 8
        case NewCredentials:     // 9
            return true;
        default:
            return false;
        }
    }

    const wchar_t* LogonTypeName(SECURITY_LOGON_TYPE t)
    {
        switch (t)
        {
        case Interactive:       return L"Interactive";
        case Network:           return L"Network";
        case Batch:             return L"Batch";
        case Service:           return L"Service";
        case Unlock:            return L"Unlock";
        case NetworkCleartext:  return L"NetworkCleartext";
        case NewCredentials:    return L"NewCredentials";
        case RemoteInteractive: return L"RemoteInteractive";
        case CachedInteractive: return L"CachedInteractive";
        default:                return L"Other";
        }
    }

    // A UNICODE_STRING inside the submit buffer has a Buffer field that is not
    // a pointer we may follow. Two forms reach us:
    //
    //   * an address in the CLIENT process. LSA hands us ClientBufferBase, the
    //     address the buffer had there, so the difference is the offset into
    //     our copy.
    //   * a plain offset from the start of the submit buffer. That is how
    //     Winlogon and LogonUI pack a KERB_INTERACTIVE_UNLOCK_LOGON - see
    //     KerbInteractiveUnlockLogonPack in Microsoft's credential provider
    //     sample, whose comment says the members "are not actually pointers
    //     but byte offsets into the overall buffer". The old code only knew
    //     the first form and read a packed buffer as an empty name.
    //
    // Everything is bounds-checked against the submit buffer. Anything off
    // copies nothing and the caller fails safe. Writes into a caller buffer:
    // no heap, no CRT.
    bool ReadClientString(const UNICODE_STRING& us,
                          const void* submitBase, const void* clientBase, ULONG submitSize,
                          WCHAR* out, SIZE_T outCap, SIZE_T& outCch)
    {
        outCch = 0;
        if (outCap)
            out[0] = L'\0';

        if (!submitBase || !outCap || !us.Buffer || us.Length == 0 ||
            (us.Length % sizeof(WCHAR)) != 0)
            return false;

        const ULONG_PTR p    = reinterpret_cast<ULONG_PTR>(us.Buffer);
        const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(clientBase);

        ULONG_PTR off = 0;
        if (clientBase && p >= base && (p - base) <= submitSize)
            off = p - base;                 // client address, relocated
        else if (p < submitSize)
            off = p;                        // already an offset
        else
            return false;

        if ((off % sizeof(WCHAR)) != 0 || us.Length > submitSize - off)
            return false;

        const WCHAR* s = reinterpret_cast<const WCHAR*>(
            static_cast<const BYTE*>(submitBase) + off);

        SIZE_T cch = us.Length / sizeof(WCHAR);
        if (cch > outCap - 1)
            cch = outCap - 1;

        SIZE_T n = 0;
        while (n < cch && s[n] != L'\0')
        {
            out[n] = s[n];
            ++n;
        }
        out[n] = L'\0';
        outCch = n;
        return n > 0;
    }

    // What the decision produced. A plain struct with fixed buffers, so the
    // __try frame in the export holds nothing that needs unwinding.
    struct Decision
    {
        bool             deny;
        bool             haveName;
        tac::Enrollment  enrolled;
        WCHAR            name[kApNameCch];
        SIZE_T           nameCch;
    };

    // The account check. We read ONLY the user name from the submit buffer
    // (never the password field) and ask the store, with a single registry
    // read, whether that name is enrolled. EnrollmentByName does no DPAPI and
    // no LSA name/SID lookup, so it is safe on the logon path, and it does not
    // allocate.
    //
    // The name is what the CLIENT typed, and the name index is not updated by
    // a rename (see store.h), so this check is weaker than the RID check in
    // the sub-authentication filter. It does not matter here - this package
    // never lets a logon through either way (see ap.h) - but do not copy it
    // into anything that does.
    void Decide(SECURITY_LOGON_TYPE logonType, PVOID submit, ULONG size, PVOID clientBase,
                Decision& d)
    {
        d.deny     = false;
        d.haveName = false;
        d.enrolled = tac::Enrollment::No;
        d.name[0]  = L'\0';
        d.nameCch  = 0;

        // The name first, for every logon type: LSA writes AccountName into
        // the audit record whatever we decide.
        if (!submit || size < sizeof(KERB_INTERACTIVE_LOGON))
            return;

        auto* k = static_cast<const KERB_INTERACTIVE_LOGON*>(submit);
        if (k->MessageType != KerbInteractiveLogon &&
            k->MessageType != KerbWorkstationUnlockLogon)
            return;

        d.haveName = ReadClientString(k->UserName, submit, clientBase, size,
                                      d.name, ARRAYSIZE(d.name), d.nameCch);

        if (!IsNonInteractive(logonType))
            return;                         // the tile already asked for a code
        if (!d.haveName)
            return;

        d.enrolled = tac::EnrollmentByName(d.name, d.nameCch);

        // Yes and Unknown both deny. "Could not tell" must never come out as
        // "not enrolled" - the same rule the sub-authentication filter follows.
        d.deny = d.enrolled != tac::Enrollment::No;
    }

    // LSA puts this in the audit record and frees it itself, so the account
    // name has to come from the LSA heap. The documentation of
    // LSA_AP_LOGON_USER_EX2 says it "must always be returned regardless of the
    // success or failure of the call"; this package used to leave it null.
    PUNICODE_STRING AllocAccountName(const WCHAR* name, SIZE_T cch)
    {
        if (!g_lsa || !g_lsa->AllocateLsaHeap || !g_lsa->FreeLsaHeap)
            return nullptr;
        if (cch > kApNameCch - 1)
            cch = kApNameCch - 1;

        auto* us = static_cast<PUNICODE_STRING>(
            g_lsa->AllocateLsaHeap(sizeof(UNICODE_STRING)));
        if (!us)
            return nullptr;

        const USHORT cb = static_cast<USHORT>(cch * sizeof(WCHAR));
        WCHAR* buf = static_cast<WCHAR*>(g_lsa->AllocateLsaHeap(cb + sizeof(WCHAR)));
        if (!buf)
        {
            g_lsa->FreeLsaHeap(us);
            return nullptr;
        }

        for (SIZE_T i = 0; i < cch; ++i)
            buf[i] = name[i];
        buf[cch] = L'\0';

        us->Length        = cb;
        us->MaximumLength = static_cast<USHORT>(cb + sizeof(WCHAR));
        us->Buffer        = buf;
        return us;
    }
}

NTSTATUS NTAPI LsaApInitializePackage(
    ULONG AuthenticationPackageId,
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    PLSA_STRING /*Database*/,
    PLSA_STRING /*Confidentiality*/,
    PLSA_STRING* AuthenticationPackageName)
{
    if (!LsaDispatchTable || !AuthenticationPackageName)
        return STATUS_INVALID_PARAMETER;
    *AuthenticationPackageName = nullptr;

    g_lsa       = LsaDispatchTable;
    g_packageId = AuthenticationPackageId;

    static const char kName[] = "TacAuthPackage";
    const USHORT len = sizeof(kName) - 1;

    char* buf = static_cast<char*>(g_lsa->AllocateLsaHeap(len + 1));
    if (!buf)
        return STATUS_NO_MEMORY;
    memcpy(buf, kName, len + 1);

    LSA_STRING* name = static_cast<LSA_STRING*>(g_lsa->AllocateLsaHeap(sizeof(LSA_STRING)));
    if (!name)
    {
        g_lsa->FreeLsaHeap(buf);
        return STATUS_NO_MEMORY;
    }
    name->Length        = len;
    name->MaximumLength = len + 1;
    name->Buffer        = buf;
    *AuthenticationPackageName = name;

    // LSA loads authentication packages while it starts, before the Eventlog
    // service is running, so event 200 normally goes nowhere at boot. The
    // [Doppio-AP] debugger line is the one you can rely on here.
    WCHAR text[160];
    tac::Buf b(text, ARRAYSIZE(text));
    b.Str(L"LSA authentication package loaded (id ");
    b.U64(AuthenticationPackageId);
    b.Str(L").");
    ApLog(EVENTLOG_INFORMATION_TYPE, 200, text);

    return STATUS_SUCCESS;
}

// We only ever DENY or decline here; we never mint a token. The deny path
// returns STATUS_ACCOUNT_RESTRICTION with the reason in SubStatus. Otherwise we
// return STATUS_INVALID_LOGON_TYPE to say "this package does not handle this
// logon". Note: a caller that selects this package by id has its logon fail
// here either way; it is not transparently retried against MSV1_0. Standard
// network/batch logons do not address this package at all - that is what the
// sub-authentication filter (subauth.cpp) is for. See the article, "deny is
// easy, success is hard".
NTSTATUS NTAPI LsaApLogonUserEx2(
    PLSA_CLIENT_REQUEST /*ClientRequest*/,
    SECURITY_LOGON_TYPE LogonType,
    PVOID ProtocolSubmitBuffer,
    PVOID ClientBufferBase,
    ULONG SubmitBufferSize,
    PVOID* ProfileBuffer,
    PULONG ProfileBufferSize,
    PLUID /*LogonId*/,
    PNTSTATUS SubStatus,
    PLSA_TOKEN_INFORMATION_TYPE /*TokenInformationType*/,
    PVOID* /*TokenInformation*/,
    PUNICODE_STRING* AccountName,
    PUNICODE_STRING* AuthenticatingAuthority,
    PUNICODE_STRING* MachineName,
    PSECPKG_PRIMARY_CRED /*PrimaryCredentials*/,
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY* CachedCredentials)
{
    if (ProfileBuffer)            *ProfileBuffer = nullptr;
    if (ProfileBufferSize)        *ProfileBufferSize = 0;
    if (SubStatus)                *SubStatus = STATUS_SUCCESS;
    if (AccountName)              *AccountName = nullptr;
    if (AuthenticatingAuthority)  *AuthenticatingAuthority = nullptr;
    if (MachineName)              *MachineName = nullptr;
    if (CachedCredentials)        *CachedCredentials = nullptr;

    Decision d = {};
    bool faulted = false;

    // A bad pointer in the submit buffer would otherwise take lsass down with
    // it, and with it the machine. Nothing in Decide allocates, so there is no
    // state to unwind.
    __try
    {
        Decide(LogonType, ProtocolSubmitBuffer, SubmitBufferSize, ClientBufferBase, d);
    }
    __except (tac::LsaDecisionExceptionFilter(GetExceptionCode()))
    {
        faulted    = true;
        d.deny     = IsNonInteractive(LogonType);   // fail closed
        d.haveName = false;
        d.nameCch  = 0;
        d.name[0]  = L'\0';
    }

    WCHAR text[320];
    tac::Buf b(text, ARRAYSIZE(text));

    NTSTATUS status;
    if (d.deny)
    {
        b.Str(L"Denied a ");
        b.Str(LogonTypeName(LogonType));
        b.Str(L" logon for '");
        b.Str(d.haveName ? d.name : L"?");
        b.Str(faulted ? L"' after an exception while deciding."
                      : (d.enrolled == tac::Enrollment::Unknown
                             ? L"': the enrollment index could not be read."
                             : L"': an enrolled account. This path has no second factor."));
        ApLog(EVENTLOG_WARNING_TYPE, 201, text);

        if (SubStatus) *SubStatus = STATUS_INVALID_WORKSTATION;
        status = STATUS_ACCOUNT_RESTRICTION;
    }
    else
    {
        // Not "passed on": nothing is forwarded anywhere. The caller asked for
        // this package, and this package never builds a token, so the logon
        // fails.
        b.Str(L"Declined a ");
        b.Str(LogonTypeName(LogonType));
        b.Str(L" logon addressed to this package. It fails; this package never "
              L"builds a token.");
        ApLog(EVENTLOG_INFORMATION_TYPE, 202, text);

        status = STATUS_INVALID_LOGON_TYPE;
    }

    // Always, success or failure: LSA writes it to the audit record and frees
    // it. A name we could not read is reported as "-" rather than left null.
    if (AccountName)
        *AccountName = d.haveName ? AllocAccountName(d.name, d.nameCch)
                                  : AllocAccountName(L"-", 1);

    return status;
}

static NTSTATUS CallStub(PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength,
                         PNTSTATUS ProtocolStatus)
{
    if (ProtocolReturnBuffer) *ProtocolReturnBuffer = nullptr;
    if (ReturnBufferLength)   *ReturnBufferLength = 0;
    if (ProtocolStatus)       *ProtocolStatus = STATUS_NOT_IMPLEMENTED;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI LsaApCallPackage(PLSA_CLIENT_REQUEST, PVOID, PVOID, ULONG,
                                PVOID* rb, PULONG rl, PNTSTATUS ps)
{ return CallStub(rb, rl, ps); }

NTSTATUS NTAPI LsaApCallPackageUntrusted(PLSA_CLIENT_REQUEST, PVOID, PVOID, ULONG,
                                         PVOID* rb, PULONG rl, PNTSTATUS ps)
{ return CallStub(rb, rl, ps); }

NTSTATUS NTAPI LsaApCallPackagePassthrough(PLSA_CLIENT_REQUEST, PVOID, PVOID, ULONG,
                                           PVOID* rb, PULONG rl, PNTSTATUS ps)
{ return CallStub(rb, rl, ps); }

VOID NTAPI LsaApLogonTerminated(PLUID /*LogonId*/)
{
}
