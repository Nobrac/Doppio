#pragma once
//
// Doppio MSV1_0 sub-authentication package (SKELETON).
//
// A sub-authentication package is called by MSV1_0 *during* its own logon
// processing. Unlike a top-level authentication package, it does not have to
// build a token or validate the password itself: MSV1_0 does all of that. The
// sub-auth routine only returns a decision - approve (STATUS_SUCCESS) or refuse
// (a failure status) - and MSV1_0 acts on it. That is why this is the right
// place to add a factor: MSV1_0 owns the credentials and the token, we only
// veto.
//
// This is also the layer that actually sees MSV1_0's network logons, which a
// top-level package addressed only to itself does not.
//
// Policy of this skeleton: refuse a NETWORK logon for an enrolled account (no UI
// to type a code there), and approve everything else so MSV1_0 finishes the
// logon normally.
//
// It is registered under:
//   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
//     Auth<N> (REG_SZ) = TacSubAuth
// and MSV1_0 calls it for logons that select sub-auth package <N>. See the
// article chapter "2FA inside LSA" for exactly what that does and does not
// cover, and for the credential-safety line this code holds.
//
// WARNING: runs in lsass.exe. A bug can leave the machine unbootable. Throwaway
// VM, snapshot, kernel debugger only.

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <subauth.h>

extern "C"
{
    NTSTATUS NTAPI Msv1_0SubAuthenticationRoutine(
        NETLOGON_LOGON_INFO_CLASS LogonLevel,
        PVOID LogonInformation,
        ULONG Flags,
        PUSER_ALL_INFORMATION UserAll,
        PULONG WhichFields,
        PULONG UserFlags,
        PBOOLEAN Authoritative,
        PLARGE_INTEGER LogoffTime,
        PLARGE_INTEGER KickoffTime);
}
