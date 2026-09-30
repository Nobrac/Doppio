#include "helpers.h"
#include <shlwapi.h>
#include <strsafe.h>

#define SECURITY_WIN32
#include <security.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "shlwapi.lib")

static void InitUnicodeString(UNICODE_STRING* pus, PWSTR pwz)
{
    // A UNICODE_STRING length is a USHORT (bytes). Cap the character count so
    // len * sizeof(WCHAR) can never wrap to a small value while Buffer still
    // points at the full string. No real password comes close to this.
    size_t len = pwz ? wcslen(pwz) : 0;
    const size_t maxChars = (0xFFFF / sizeof(WCHAR)) - 1;   // 32766
    if (len > maxChars)
        len = maxChars;

    pus->Length        = static_cast<USHORT>(len * sizeof(WCHAR));
    pus->MaximumLength = static_cast<USHORT>((len + 1) * sizeof(WCHAR));
    pus->Buffer        = pwz;
}

// Copies the string to pbDest and stores its offset from pvBase in Buffer.
static void PackUnicodeString(const UNICODE_STRING& src, UNICODE_STRING* pusDst,
                              BYTE* pbDest, const void* pvBase)
{
    pusDst->Length        = src.Length;
    pusDst->MaximumLength = src.Length;
    if (src.Length)
    {
        CopyMemory(pbDest, src.Buffer, src.Length);
        pusDst->Buffer = reinterpret_cast<PWSTR>(
            static_cast<ULONG_PTR>(pbDest - static_cast<const BYTE*>(pvBase)));
    }
    else
    {
        pusDst->Buffer = nullptr;
    }
}

static bool UnpackUnicodeString(void* pvBase, DWORD cb, UNICODE_STRING* pus)
{
    if (pus->Length == 0)
    {
        pus->Buffer = nullptr;
        return true;
    }

    ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(pus->Buffer);
    if (offset % sizeof(WCHAR) != 0 || offset > cb || pus->Length > cb - offset)
        return false;

    pus->Buffer = reinterpret_cast<PWSTR>(static_cast<BYTE*>(pvBase) + offset);
    return true;
}

HRESULT SplitDomainAndUsername(PCWSTR pszQualifiedUserName,
                               PWSTR pszDomain, int cchDomain,
                               PWSTR pszUsername, int cchUsername)
{
    const wchar_t* pchSlash = wcschr(pszQualifiedUserName, L'\\');
    if (!pchSlash)
        return E_INVALIDARG;

    HRESULT hr = StringCchCopyNW(pszDomain, cchDomain, pszQualifiedUserName,
                                 static_cast<size_t>(pchSlash - pszQualifiedUserName));
    if (SUCCEEDED(hr))
        hr = StringCchCopyW(pszUsername, cchUsername, pchSlash + 1);
    return hr;
}

HRESULT ProtectIfNecessaryAndCopyPassword(PCWSTR pwzPassword,
                                          CREDENTIAL_PROVIDER_USAGE_SCENARIO,
                                          PWSTR* ppwzProtectedPassword)
{
    // The Microsoft sample runs the password through CredProtect first. A plain
    // copy works for a local logon and keeps this demo small.
    *ppwzProtectedPassword = nullptr;
    return SHStrDupW(pwzPassword ? pwzPassword : L"", ppwzProtectedPassword);
}

HRESULT KerbInteractiveUnlockLogonInit(PWSTR pwzDomain, PWSTR pwzUsername, PWSTR pwzPassword,
                                       CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                       KERB_INTERACTIVE_UNLOCK_LOGON* pkiul)
{
    ZeroMemory(pkiul, sizeof(*pkiul));
    KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;

    switch (cpus)
    {
    case CPUS_LOGON:              pkil->MessageType = KerbInteractiveLogon;       break;
    case CPUS_UNLOCK_WORKSTATION: pkil->MessageType = KerbWorkstationUnlockLogon; break;
    default:                      return E_INVALIDARG;
    }

    InitUnicodeString(&pkil->LogonDomainName, pwzDomain);
    InitUnicodeString(&pkil->UserName, pwzUsername);
    InitUnicodeString(&pkil->Password, pwzPassword);
    return S_OK;
}

HRESULT KerbInteractiveUnlockLogonPack(const KERB_INTERACTIVE_UNLOCK_LOGON& rkiulIn,
                                       BYTE** prgb, DWORD* pcb)
{
    const KERB_INTERACTIVE_LOGON& in = rkiulIn.Logon;
    DWORD cb = sizeof(rkiulIn) + in.LogonDomainName.Length + in.UserName.Length + in.Password.Length;

    KERB_INTERACTIVE_UNLOCK_LOGON* pkiulOut =
        static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(CoTaskMemAlloc(cb));
    if (!pkiulOut)
        return E_OUTOFMEMORY;

    ZeroMemory(pkiulOut, sizeof(*pkiulOut));
    pkiulOut->Logon.MessageType = in.MessageType;

    BYTE* pbData = reinterpret_cast<BYTE*>(pkiulOut) + sizeof(*pkiulOut);
    PackUnicodeString(in.LogonDomainName, &pkiulOut->Logon.LogonDomainName, pbData, pkiulOut);
    pbData += in.LogonDomainName.Length;
    PackUnicodeString(in.UserName, &pkiulOut->Logon.UserName, pbData, pkiulOut);
    pbData += in.UserName.Length;
    PackUnicodeString(in.Password, &pkiulOut->Logon.Password, pbData, pkiulOut);

    *prgb = reinterpret_cast<BYTE*>(pkiulOut);
    *pcb  = cb;
    return S_OK;
}

HRESULT KerbInteractiveUnlockLogonUnpackInPlace(KERB_INTERACTIVE_UNLOCK_LOGON* pkiul, DWORD cb)
{
    if (cb < sizeof(*pkiul))
        return E_INVALIDARG;

    KERB_INTERACTIVE_LOGON* pkil = &pkiul->Logon;
    if (UnpackUnicodeString(pkiul, cb, &pkil->LogonDomainName) &&
        UnpackUnicodeString(pkiul, cb, &pkil->UserName) &&
        UnpackUnicodeString(pkiul, cb, &pkil->Password))
        return S_OK;
    return E_INVALIDARG;
}

HRESULT RetrieveNegotiateAuthPackage(ULONG* pulAuthPackage)
{
    HANDLE hLsa = nullptr;
    NTSTATUS status = LsaConnectUntrusted(&hLsa);
    if (status != 0)
        return HRESULT_FROM_NT(status);

    LSA_STRING name;
    name.Buffer        = const_cast<PCHAR>(NEGOSSP_NAME_A);
    name.Length        = static_cast<USHORT>(strlen(name.Buffer));
    name.MaximumLength = static_cast<USHORT>(name.Length + 1);

    ULONG ulPackage = 0;
    status = LsaLookupAuthenticationPackage(hLsa, &name, &ulPackage);
    LsaDeregisterLogonProcess(hLsa);
    if (status != 0)
        return HRESULT_FROM_NT(status);

    *pulAuthPackage = ulPackage;
    return S_OK;
}

HRESULT FieldDescriptorCoAllocCopy(const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
                                   CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    *ppcpfd = nullptr;

    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd =
        static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(
            CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!pcpfd)
        return E_OUTOFMEMORY;

    pcpfd->dwFieldID     = rcpfd.dwFieldID;
    pcpfd->cpft          = rcpfd.cpft;
    pcpfd->guidFieldType = rcpfd.guidFieldType;
    pcpfd->pszLabel      = nullptr;

    HRESULT hr = S_OK;
    if (rcpfd.pszLabel)
        hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);

    if (SUCCEEDED(hr))
        *ppcpfd = pcpfd;
    else
        CoTaskMemFree(pcpfd);
    return hr;
}
