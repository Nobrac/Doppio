#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <ntsecapi.h>

// Trimmed versions of the helpers from Microsoft's credential provider sample
// (Windows-classic-samples, Security/CredentialProvider).

HRESULT SplitDomainAndUsername(PCWSTR pszQualifiedUserName,
                               PWSTR pszDomain, int cchDomain,
                               PWSTR pszUsername, int cchUsername);

HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                          PWSTR* ppwzProtectedPassword);

// Fills the structure with pointers to the caller's strings (no copies).
HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       KERB_INTERACTIVE_UNLOCK_LOGON* pkiul);

// One CoTaskMem buffer: the structure, followed by the string data. The string
// pointers are replaced by offsets from the start of the buffer.
HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
                                       BYTE** prgb, DWORD* pcb);

// Turns the offsets back into pointers, with bounds checks. Used for
// credentials forwarded by RDP.
HRESULT KerbInteractiveUnlockLogonUnpackInPlace(KERB_INTERACTIVE_UNLOCK_LOGON* pkiul, DWORD cb);

HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage);

HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
