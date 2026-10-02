#include "CTacFilter.h"
#include "guid.h"
#include "dll.h"
#include "store.h"
#include <new>

IFACEMETHODIMP_(ULONG) CTacFilter::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CTacFilter::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0)
        delete this;
    return cRef;
}

IFACEMETHODIMP CTacFilter::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(ICredentialProviderFilter)))
    {
        *ppv = static_cast<ICredentialProviderFilter*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// Allow only our provider on the logon and unlock screens, so the code cannot
// be skipped by picking the password or PIN tile. That deliberately goes
// against Microsoft's advice to always keep one of their providers: with one
// left visible, the second factor would be optional. The recovery story is
// therefore:
//   - If TacProvider.dll cannot be loaded, this filter (same DLL) cannot be
//     created either, and LogonUI skips it - every provider shows again.
//     Worth confirming once in the VM by renaming the DLL.
//   - While no account is enrolled at all (filter imported too early, or after
//     `enroll /purge`), nothing is hidden.
//   - Our provider always offers an "Other user" tile at logon, for accounts
//     Windows does not list (a hidden break-glass admin).
//   - Otherwise: WinRE, delete the filter key offline (see README).
// Other scenarios (CredUI, change password, PLAP) are left alone, or we would
// break unrelated prompts.
IFACEMETHODIMP CTacFilter::Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD,
                                  GUID* rgclsidProviders, BOOL* rgbAllow, DWORD cProviders)
{
    if (cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION)
        return S_OK;
    if (!rgclsidProviders || !rgbAllow)
        return E_POINTER;

    // Nothing enrolled: hiding the other tiles would only lock everyone out.
    // A store that cannot be read is NOT treated as empty - filter as usual.
    bool any = false;
    if (tac::QueryAnyEnrollment(any) && !any)
        return S_OK;

    for (DWORD i = 0; i < cProviders; ++i)
        rgbAllow[i] = IsEqualGUID(rgclsidProviders[i], CLSID_CTacProvider);
    return S_OK;
}

// RDP with NLA delivers the credential before a tile exists. We forward it and
// set the target provider to ourselves; copying the incoming CLSID would send
// it to a provider we just filtered out, and remote logon would break.
IFACEMETHODIMP CTacFilter::UpdateRemoteCredential(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut)
{
    if (!pcpcsOut)
        return E_POINTER;
    ZeroMemory(pcpcsOut, sizeof(*pcpcsOut));
    if (!pcpcsIn || pcpcsIn->cbSerialization == 0 || !pcpcsIn->rgbSerialization)
        return E_NOTIMPL;

    pcpcsOut->rgbSerialization =
        static_cast<BYTE*>(CoTaskMemAlloc(pcpcsIn->cbSerialization));
    if (!pcpcsOut->rgbSerialization)
        return E_OUTOFMEMORY;

    CopyMemory(pcpcsOut->rgbSerialization, pcpcsIn->rgbSerialization, pcpcsIn->cbSerialization);
    pcpcsOut->cbSerialization         = pcpcsIn->cbSerialization;
    pcpcsOut->ulAuthenticationPackage = pcpcsIn->ulAuthenticationPackage;
    pcpcsOut->clsidCredentialProvider = CLSID_CTacProvider;
    return S_OK;
}

HRESULT CTacFilter_CreateInstance(REFIID riid, void** ppv)
{
    CTacFilter* filter = new (std::nothrow) CTacFilter();
    if (!filter)
        return E_OUTOFMEMORY;
    HRESULT hr = filter->QueryInterface(riid, ppv);
    filter->Release();
    return hr;
}
