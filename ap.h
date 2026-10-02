#pragma once
//
// Doppio LSA authentication package (SKELETON).
//
// This runs inside LSA (lsass.exe), not in LogonUI. An authentication package
// is only invoked for logons that address it by package id, so by itself it
// does NOT see the standard network/batch logon paths - those go to MSV1_0 /
// Negotiate. To gate those, see the sub-authentication filter (subauth.cpp),
// which MSV1_0 calls after it has validated a logon.
//
// Policy of this skeleton: for an enrolled account, deny every NON-interactive
// logon that reaches us. Interactive and unlock are left to the credential
// provider, which already asks for the TOTP.
//
// Be clear about what that is worth: NOTHING as a security control. A logon
// only reaches this package if the caller asks for it by package id, and every
// such logon fails anyway - denied, or declined with STATUS_NOT_IMPLEMENTED,
// because this package never builds a token. No real logon path is closed by
// loading it. It is here to show the LSA package interface and the logging,
// nothing more. The path that actually matters is the sub-authentication
// filter (subauth.cpp) or, on a real machine, the user rights.
//
// WARNING: this code runs in lsass.exe. A bug here does not fail one tile - it
// can crash LSA and leave the machine unbootable, past Safe Mode. Only ever
// load it in a throwaway VM with a snapshot, and debug it over a kernel
// debugger (WinDbg on a second machine). See the article chapter
// "2FA inside LSA" for the setup and the honest limits.
//
// The exports are looked up by name by LSA, so they are C-linkage and listed
// in TacAuthPackage.def.

#define SECURITY_WIN32
#include <windows.h>
#include <sspi.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>

extern "C"
{
    NTSTATUS NTAPI LsaApInitializePackage(
        ULONG AuthenticationPackageId,
        PLSA_DISPATCH_TABLE LsaDispatchTable,
        PLSA_STRING Database,
        PLSA_STRING Confidentiality,
        PLSA_STRING* AuthenticationPackageName);

    NTSTATUS NTAPI LsaApLogonUserEx2(
        PLSA_CLIENT_REQUEST ClientRequest,
        SECURITY_LOGON_TYPE LogonType,
        PVOID ProtocolSubmitBuffer,
        PVOID ClientBufferBase,
        ULONG SubmitBufferSize,
        PVOID* ProfileBuffer,
        PULONG ProfileBufferSize,
        PLUID LogonId,
        PNTSTATUS SubStatus,
        PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
        PVOID* TokenInformation,
        PUNICODE_STRING* AccountName,
        PUNICODE_STRING* AuthenticatingAuthority,
        PUNICODE_STRING* MachineName,
        PSECPKG_PRIMARY_CRED PrimaryCredentials,
        PSECPKG_SUPPLEMENTAL_CRED_ARRAY* CachedCredentials);

    NTSTATUS NTAPI LsaApCallPackage(
        PLSA_CLIENT_REQUEST ClientRequest, PVOID ProtocolSubmitBuffer,
        PVOID ClientBufferBase, ULONG SubmitBufferLength,
        PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength,
        PNTSTATUS ProtocolStatus);

    NTSTATUS NTAPI LsaApCallPackageUntrusted(
        PLSA_CLIENT_REQUEST ClientRequest, PVOID ProtocolSubmitBuffer,
        PVOID ClientBufferBase, ULONG SubmitBufferLength,
        PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength,
        PNTSTATUS ProtocolStatus);

    NTSTATUS NTAPI LsaApCallPackagePassthrough(
        PLSA_CLIENT_REQUEST ClientRequest, PVOID ProtocolSubmitBuffer,
        PVOID ClientBufferBase, ULONG SubmitBufferLength,
        PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength,
        PNTSTATUS ProtocolStatus);

    VOID NTAPI LsaApLogonTerminated(PLUID LogonId);
}
