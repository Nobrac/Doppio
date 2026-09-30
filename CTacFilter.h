#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include "dll.h"

// Hides every credential provider except ours on the logon and unlock screens.
// A provider only adds a tile; the filter is what makes the second factor
// unavoidable, by removing the password, PIN and Windows Hello tiles.
class CTacFilter : public ICredentialProviderFilter
{
public:
    CTacFilter() : _cRef(1) { DllAddRef(); }

    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    IFACEMETHODIMP Filter(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags,
                          GUID* rgclsidProviders, BOOL* rgbAllow, DWORD cProviders);
    IFACEMETHODIMP UpdateRemoteCredential(
        const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsIn,
        CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcsOut);

    friend HRESULT CTacFilter_CreateInstance(REFIID riid, void** ppv);

private:
    virtual ~CTacFilter() { DllRelease(); }
    LONG _cRef;
};
