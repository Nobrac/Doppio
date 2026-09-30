#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <string>
#include <vector>
#include "CTacCredential.h"

// Creates one tile per local user, like the built-in Windows tiles. Windows
// hands us the users through ICredentialProviderSetUserArray; because each tile
// is bound to a user (via GetUserSid), Windows draws the name and round picture.
class CTacProvider : public ICredentialProvider,
                     public ICredentialProviderSetUserArray
{
public:
    CTacProvider();

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags);
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs);
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upAdviseContext);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount);
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd);
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault);
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc);

    // ICredentialProviderSetUserArray
    IFACEMETHODIMP SetUserArray(ICredentialProviderUserArray* users);

    friend HRESULT CTacProvider_CreateInstance(REFIID riid, void** ppv);

private:
    virtual ~CTacProvider();

    void    _ClearCredentials();
    HRESULT _CreateCredentials();
    HRESULT _AddCredential(PCWSTR pwzUser, PCWSTR pwzPassword, PCWSTR pwzSid);

    LONG                               _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO _cpus;
    ICredentialProviderUserArray*      _pUserArray;
    std::vector<CTacCredential*>       _credentials;
    bool                               _built;
    DWORD                              _defaultIndex;

    // Set by SetSerialization when RDP forwards a credential to us.
    bool                               _haveRemote;
    std::wstring                       _remoteUser;
    std::wstring                       _remotePassword;
};
