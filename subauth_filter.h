#pragma once
//
// (Named subauth_filter.h, not subauth.h: with the project folder on the
// include path, a project header called subauth.h would hide the SDK header
// of the same name that this file includes.)
//
// Doppio MSV1_0 sub-authentication FILTER (SKELETON).
//
// MSV1_0 has two sub-authentication hooks, and they are very different:
//
//   Msv1_0SubAuthenticationRoutine (Auth1..AuthN)
//       Called only for logons whose request explicitly selects package N in
//       ParameterControl - ordinary SMB/NTLM logons never do. And when it IS
//       called, authentication is its job: MSV1_0 hands it the challenge
//       response and the SAM hashes and trusts its answer. Returning
//       STATUS_SUCCESS there approves the logon without any password check.
//       That is the wrong seam for a veto, and this project no longer uses it.
//
//   Msv1_0SubAuthenticationFilter (Auth0)
//       Called AFTER MSV1_0 has validated the logon, as an additional check.
//       STATUS_SUCCESS means "no objection, proceed", a failure status vetoes.
//       MSV1_0 keeps the password check, the account restrictions and the
//       token. This is the seam a second-factor veto belongs in.
//
// Policy of this skeleton: refuse a NETWORK logon for an enrolled account (no UI
// to type a code there), and raise no objection to anything else.
//
// The account is identified by the RID that MSV1_0 read from the SAM
// (USER_ALL_INFORMATION::UserId), not by the name the client sent. The RID
// survives a rename and cannot be spelled differently.
//
// It is registered under:
//   HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0
//     Auth0 (REG_SZ) = TacSubAuth
// Microsoft documents Auth0 for the domain controller's registry. Whether the
// filter also runs for local SAM accounts on a workstation is exactly what to
// verify in the test VM: every call writes a [Doppio-SubAuth] OutputDebugString
// line, readable under the kernel debugger.
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
    NTSTATUS NTAPI Msv1_0SubAuthenticationFilter(
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
