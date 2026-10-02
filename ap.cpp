#include "ap.h"
#include "store.h"
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

// NTSTATUS values we return. They live in ntstatus.h, which clashes with
// windows.h, so we define the handful we need.
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)  // "account not allowed to log on here/now"
#endif
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED    ((NTSTATUS)0xC0000002L)
#endif

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

    // Logging from inside lsass. OutputDebugStringW is the channel you actually
    // read under a kernel debugger. ReportEvent is best-effort on top, guarded
    // so a logging failure can never affect a logon. We never log a password or
    // a code, only metadata.
    void ApLog(WORD type, DWORD id, const std::wstring& text)
    {
        OutputDebugStringW((L"[Doppio-AP] " + text + L"\n").c_str());

        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text.c_str() };
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

    // A UNICODE_STRING inside the submit buffer has a Buffer pointer that is
    // valid in the CLIENT process, not ours. LSA gives us ClientBufferBase (the
    // address the buffer had in the client) so we can relocate it into our copy.
    // Everything is bounds-checked against the submit buffer; anything off
    // returns an empty string, and the caller fails safe.
    std::wstring ReadClientString(const UNICODE_STRING& us,
                                  const void* submitBase, const void* clientBase,
                                  ULONG submitSize)
    {
        if (!us.Buffer || us.Length == 0 || (us.Length % sizeof(WCHAR)) != 0)
            return std::wstring();

        const ULONG_PTR p    = reinterpret_cast<ULONG_PTR>(us.Buffer);
        const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(clientBase);
        if (p < base)
            return std::wstring();

        const ULONG_PTR off = p - base;
        if (off > submitSize || us.Length > submitSize - off)
            return std::wstring();

        const WCHAR* s = reinterpret_cast<const WCHAR*>(
            static_cast<const BYTE*>(submitBase) + off);
        return std::wstring(s, us.Length / sizeof(WCHAR));
    }

    // The account check. We read ONLY the user name from the submit buffer
    // (never the password field) and ask the store, with a single registry
    // read, whether that name is enrolled. IsEnrolledByName does no DPAPI and
    // no LSA name/SID lookup, so it is safe on the logon path. Any
    // inconsistency returns false (treat as not enrolled -> defer), so a
    // malformed buffer cannot crash us.
    //
    // The name is what the CLIENT typed, and the name index is not updated by
    // a rename (see store.h), so this check is weaker than the RID check in
    // the sub-authentication filter. It does not matter here - this package
    // never lets a logon through either way (see ap.h) - but do not copy it
    // into anything that does.
    bool IsEnrolledAccount(PVOID submit, ULONG size, PVOID clientBase)
    {
        if (!submit || size < sizeof(KERB_INTERACTIVE_LOGON))
            return false;

        auto* k = static_cast<const KERB_INTERACTIVE_LOGON*>(submit);
        if (k->MessageType != KerbInteractiveLogon &&
            k->MessageType != KerbWorkstationUnlockLogon)
            return false;

        std::wstring user = ReadClientString(k->UserName, submit, clientBase, size);
        if (user.empty())
            return false;

        return tac::IsEnrolledByName(user);
    }
}

NTSTATUS NTAPI LsaApInitializePackage(
    ULONG AuthenticationPackageId,
    PLSA_DISPATCH_TABLE LsaDispatchTable,
    PLSA_STRING /*Database*/,
    PLSA_STRING /*Confidentiality*/,
    PLSA_STRING* AuthenticationPackageName)
{
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

    ApLog(EVENTLOG_INFORMATION_TYPE, 200,
          L"LSA authentication package loaded (id " + std::to_wstring(AuthenticationPackageId) + L").");
    return STATUS_SUCCESS;
}

// We only ever DENY or decline here; we never mint a token. The deny path
// returns STATUS_ACCOUNT_RESTRICTION. Otherwise we return STATUS_NOT_IMPLEMENTED
// to say "this package does not handle this logon". Note: a caller that selects
// this package by id and gets STATUS_NOT_IMPLEMENTED has its logon fail here; it
// is not transparently retried against MSV1_0. Standard network/batch logons do
// not address this package at all - that is what the sub-authentication package
// (subauth.cpp) is for. See the article, "deny is easy, success is hard".
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

    const bool nonInteractive = IsNonInteractive(LogonType);
    const bool enrolled       = nonInteractive &&
                                IsEnrolledAccount(ProtocolSubmitBuffer, SubmitBufferSize, ClientBufferBase);

    if (nonInteractive && enrolled)
    {
        ApLog(EVENTLOG_WARNING_TYPE, 201,
              std::wstring(L"Denied a ") + LogonTypeName(LogonType) +
              L" logon for an enrolled account. This path has no second factor.");
        if (SubStatus) *SubStatus = STATUS_ACCOUNT_RESTRICTION;
        return STATUS_ACCOUNT_RESTRICTION;
    }

    ApLog(EVENTLOG_INFORMATION_TYPE, 202,
          std::wstring(L"Passed a ") + LogonTypeName(LogonType) + L" logon to the normal packages.");
    return STATUS_NOT_IMPLEMENTED;
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
