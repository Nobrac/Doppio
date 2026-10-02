#include "subauth.h"
#include "store.h"
#include <string>
#include <vector>

#pragma comment(lib, "advapi32.lib")

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS             ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_ACCOUNT_RESTRICTION
#define STATUS_ACCOUNT_RESTRICTION ((NTSTATUS)0xC000006EL)
#endif

namespace
{
    void SaLog(WORD type, DWORD id, const std::wstring& text)
    {
        OutputDebugStringW((L"[Doppio-SubAuth] " + text + L"\n").c_str());

        HANDLE h = RegisterEventSourceW(nullptr, L"TheAdminCafe 2FA");
        if (h)
        {
            LPCWSTR s[1] = { text.c_str() };
            ReportEventW(h, type, 0, id, nullptr, 1, 0, s, nullptr);
            DeregisterEventSource(h);
        }
    }
}

// MSV1_0 calls this during its logon processing. We decide, MSV1_0 does the
// password check and the token.
NTSTATUS NTAPI Msv1_0SubAuthenticationRoutine(
    NETLOGON_LOGON_INFO_CLASS LogonLevel,
    PVOID LogonInformation,
    ULONG /*Flags*/,
    PUSER_ALL_INFORMATION /*UserAll*/,
    PULONG WhichFields,
    PULONG UserFlags,
    PBOOLEAN Authoritative,
    PLARGE_INTEGER LogoffTime,
    PLARGE_INTEGER KickoffTime)
{
    if (WhichFields)   *WhichFields = 0;
    if (UserFlags)     *UserFlags = 0;
    if (Authoritative) *Authoritative = TRUE;              // our decision is final
    if (LogoffTime)    LogoffTime->QuadPart  = 0x7FFFFFFFFFFFFFFFLL;   // never
    if (KickoffTime)   KickoffTime->QuadPart = 0x7FFFFFFFFFFFFFFFLL;

    if (!LogonInformation)
        return STATUS_SUCCESS;   // nothing to decide on, let MSV1_0 proceed

    // NETLOGON_INTERACTIVE_INFO and NETLOGON_NETWORK_INFO both begin with the
    // same NETLOGON_LOGON_IDENTITY_INFO, so we read the identity for either.
    //
    // IMPORTANT: we read ONLY the account name, to look up enrollment. We never
    // touch LmOwfPassword / NtOwfPassword or the challenge-response blobs that
    // sit after it. Reading and keeping that credential material is exactly the
    // theft pattern this project refuses to build - the decision never needs it.
    auto* id = static_cast<const NETLOGON_LOGON_IDENTITY_INFO*>(LogonInformation);

    std::wstring user;
    // Cap the length as defense in depth before trusting it to build a string.
    if (id->UserName.Buffer && id->UserName.Length &&
        id->UserName.Length <= 512 &&
        (id->UserName.Length % sizeof(WCHAR)) == 0)
        user.assign(id->UserName.Buffer, id->UserName.Length / sizeof(WCHAR));

    if (user.empty())
        return STATUS_SUCCESS;   // can't identify the account -> don't block

    // Is this account enrolled? A single registry read - no DPAPI, no LSA
    // name/SID lookup - so nothing here re-enters LSA from inside MSV1_0.
    const bool enrolled  = tac::IsEnrolledByName(user);
    const bool isNetwork = (LogonLevel == NetlogonNetworkInformation ||
                            LogonLevel == NetlogonNetworkTransitiveInformation);

    if (enrolled && isNetwork)
    {
        // A network logon has nowhere to type a code. For an enrolled account we
        // refuse it here, inside MSV1_0's own processing.
        SaLog(EVENTLOG_WARNING_TYPE, 210,
              L"Refused a network logon for enrolled account '" + user +
              L"'. No second factor on this path.");
        return STATUS_ACCOUNT_RESTRICTION;
    }

    // Everything else: approve, and MSV1_0 finishes the logon and mints the
    // token. This is the working "success" path - we decide, MSV1_0 builds it.
    SaLog(EVENTLOG_INFORMATION_TYPE, 211,
          L"Approved a " + std::wstring(isNetwork ? L"network" : L"non-network") +
          L" logon for '" + user + L"'. MSV1_0 completes it.");
    return STATUS_SUCCESS;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
