#include "CTacProvider.h"
#include "helpers.h"
#include "common.h"
#include "dll.h"
#include "guid.h"

#include <ntsecapi.h>
#include <new>

// System.Identity.QualifiedUserName. This is the "DOMAIN\user" (or "PC\user")
// form LSA needs. The key is defined by value here so we do not have to link
// propsys just for one property. See the Microsoft property documentation.
static const PROPERTYKEY PKEY_QualifiedUserName =
    { { 0xDA520E51, 0xF4E9, 0x4739, { 0xAC, 0x82, 0x02, 0xE0, 0xA9, 0x5C, 0x90, 0x30 } }, 100 };

CTacProvider::CTacProvider()
    : _cRef(1), _cpus(CPUS_INVALID), _pUserArray(nullptr), _built(false),
      _defaultIndex(CREDENTIAL_PROVIDER_NO_DEFAULT), _haveRemote(false)
{
    DllAddRef();
}

CTacProvider::~CTacProvider()
{
    _ClearCredentials();
    if (!_remotePassword.empty())
        SecureZeroMemory(&_remotePassword[0], _remotePassword.size() * sizeof(WCHAR));
    if (_pUserArray)
        _pUserArray->Release();
    DllRelease();
}

void CTacProvider::_ClearCredentials()
{
    for (CTacCredential* c : _credentials)
        c->Release();
    _credentials.clear();
    _built = false;
    _defaultIndex = CREDENTIAL_PROVIDER_NO_DEFAULT;
}

// --- IUnknown ---------------------------------------------------------------

IFACEMETHODIMP_(ULONG) CTacProvider::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CTacProvider::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0)
        delete this;
    return cRef;
}

IFACEMETHODIMP CTacProvider::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(ICredentialProvider)))
    {
        *ppv = static_cast<ICredentialProvider*>(this);
        AddRef();
        return S_OK;
    }
    if (IsEqualIID(riid, __uuidof(ICredentialProviderSetUserArray)))
    {
        *ppv = static_cast<ICredentialProviderSetUserArray*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// --- ICredentialProvider ----------------------------------------------------

IFACEMETHODIMP CTacProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD)
{
    switch (cpus)
    {
    case CPUS_LOGON:
    case CPUS_UNLOCK_WORKSTATION:
        _cpus = cpus;
        return S_OK;

    // We take part in logon and unlock only. Declining the rest cleanly is
    // important: misbehaving in CPUS_CREDUI would break UAC prompts.
    case CPUS_CHANGE_PASSWORD:
    case CPUS_CREDUI:
    case CPUS_PLAP:
        return E_NOTIMPL;

    default:
        return E_INVALIDARG;
    }
}

// A qualified name is local when the part before the backslash is this computer.
// "CONTOSO\alice" or "MicrosoftAccount\..." are not, and get no tile: the secret
// is stored per bare name and this demo authenticates only against the local SAM.
static bool IsLocalAccount(PCWSTR qualified)
{
    const wchar_t* slash = qualified ? wcschr(qualified, L'\\') : nullptr;
    if (!slash)
        return false;

    WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cchComputer = ARRAYSIZE(computer);
    if (!GetComputerNameW(computer, &cchComputer))
        return false;

    size_t domainLen = static_cast<size_t>(slash - qualified);
    return domainLen == cchComputer && _wcsnicmp(qualified, computer, domainLen) == 0;
}

HRESULT CTacProvider::_AddCredential(PCWSTR pwzUser, PCWSTR pwzPassword, PCWSTR pwzSid)
{
    CTacCredential* cred = new (std::nothrow) CTacCredential();
    if (!cred)
        return E_OUTOFMEMORY;

    HRESULT hr = cred->Initialize(_cpus, s_rgFieldDescriptors, s_rgFieldStatePairs,
                                  pwzUser, pwzPassword, pwzSid);
    if (SUCCEEDED(hr))
    {
        try
        {
            _credentials.push_back(cred);
            return S_OK;
        }
        catch (...)   // std::bad_alloc must not cross into LogonUI
        {
            hr = E_OUTOFMEMORY;
        }
    }
    cred->Release();
    return hr;
}

HRESULT CTacProvider::_CreateCredentials()
{
    if (_built)
        return S_OK;
    _ClearCredentials();

    // RDP path: one tile, pre-filled with the forwarded name and password.
    if (_haveRemote)
    {
        HRESULT hr = _AddCredential(_remoteUser.c_str(), _remotePassword.c_str(), nullptr);
        if (FAILED(hr))
            return hr;      // keep the forwarded credential for LogonUI's next try
        _defaultIndex = 0;

        // The tile has its own copy now, so drop ours.
        if (!_remotePassword.empty())
        {
            SecureZeroMemory(&_remotePassword[0], _remotePassword.size() * sizeof(WCHAR));
            _remotePassword.clear();
        }
        _built = true;
        return S_OK;
    }

    // One tile per listed local user. A user that cannot be read is skipped.
    // Out of memory stops the loop; if not a single tile could be created,
    // that is reported to LogonUI instead of pretending the enumeration worked.
    DWORD count = 0;
    if (_pUserArray && FAILED(_pUserArray->GetCount(&count)))
        count = 0;

    HRESULT hr = S_OK;
    for (DWORD i = 0; i < count && hr != E_OUTOFMEMORY; ++i)
    {
        ICredentialProviderUser* user = nullptr;
        if (FAILED(_pUserArray->GetAt(i, &user)) || !user)
            continue;

        PWSTR qualified = nullptr;
        PWSTR sid       = nullptr;
        if (SUCCEEDED(user->GetStringValue(PKEY_QualifiedUserName, &qualified)) &&
            SUCCEEDED(user->GetSid(&sid)) &&
            qualified && sid && IsLocalAccount(qualified))
            hr = _AddCredential(qualified, L"", sid);

        CoTaskMemFree(qualified);
        CoTaskMemFree(sid);
        user->Release();
    }

    // Always one generic tile with a username field ("Other user") at logon.
    // With the filter on, this is the only way in for an account Windows does
    // not list: a hidden break-glass admin, or any account when Windows lists
    // no users at all. On the unlock screen it is only added if nothing else
    // could be created.
    if (hr != E_OUTOFMEMORY && (_cpus == CPUS_LOGON || _credentials.empty()))
        hr = _AddCredential(L"", L"", nullptr);

    if (FAILED(hr) && _credentials.empty())
        return hr;          // nothing usable at all: say so, LogonUI retries later

    _built = true;
    return S_OK;
}

// RDP with NLA forwards the credential over CredSSP before any tile is drawn.
// We unpack it and remember the name and password to pre-fill the tile.
IFACEMETHODIMP CTacProvider::SetSerialization(
    const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs)
{
    if (!pcpcs || !pcpcs->rgbSerialization ||
        pcpcs->cbSerialization < sizeof(KERB_INTERACTIVE_UNLOCK_LOGON))
        return E_NOTIMPL;
    // Domain, name and password are each at most 64 KB (USHORT lengths); a
    // larger buffer is not a password logon, so do not copy it.
    if (pcpcs->cbSerialization > sizeof(KERB_INTERACTIVE_UNLOCK_LOGON) + 3 * 0x10000)
        return E_INVALIDARG;
    if (!IsEqualCLSID(pcpcs->clsidCredentialProvider, CLSID_CTacProvider))
        return E_NOTIMPL;   // not addressed to us

    // Work on our own copy, because unpacking rewrites the offsets to pointers.
    KERB_INTERACTIVE_UNLOCK_LOGON* pkiul =
        static_cast<KERB_INTERACTIVE_UNLOCK_LOGON*>(CoTaskMemAlloc(pcpcs->cbSerialization));
    if (!pkiul)
        return E_OUTOFMEMORY;
    CopyMemory(pkiul, pcpcs->rgbSerialization, pcpcs->cbSerialization);

    // RDP can also forward other logon types, a smartcard logon for example.
    // Only a password logon has the layout we unpack below.
    HRESULT hr = S_OK;
    if (pkiul->Logon.MessageType != KerbInteractiveLogon &&
        pkiul->Logon.MessageType != KerbWorkstationUnlockLogon)
        hr = E_NOTIMPL;

    if (SUCCEEDED(hr))
        hr = KerbInteractiveUnlockLogonUnpackInPlace(pkiul, pcpcs->cbSerialization);
    if (SUCCEEDED(hr))
    {
        const KERB_INTERACTIVE_LOGON& kil = pkiul->Logon;

        // A UNICODE_STRING is counted, not null-terminated, and Buffer can be
        // null (empty domain), which std::wstring must not be built from.
        auto toString = [](const UNICODE_STRING& us) -> std::wstring {
            if (!us.Buffer || us.Length == 0)
                return std::wstring();
            return std::wstring(us.Buffer, us.Length / sizeof(WCHAR));
        };

        try
        {
            std::wstring domain = toString(kil.LogonDomainName);
            std::wstring user   = toString(kil.UserName);
            std::wstring pass   = toString(kil.Password);

            if (!_remotePassword.empty())
                SecureZeroMemory(&_remotePassword[0], _remotePassword.size() * sizeof(WCHAR));

            _remoteUser     = domain.empty() ? user : (domain + L"\\" + user);
            _remotePassword = pass;
            _haveRemote     = true;
            _built          = false;

            if (!pass.empty())
                SecureZeroMemory(&pass[0], pass.size() * sizeof(WCHAR));
        }
        catch (...)
        {
            hr = E_OUTOFMEMORY;
        }
    }

    SecureZeroMemory(pkiul, pcpcs->cbSerialization);
    CoTaskMemFree(pkiul);
    return hr;
}

IFACEMETHODIMP CTacProvider::Advise(ICredentialProviderEvents*, UINT_PTR) { return S_OK; }
IFACEMETHODIMP CTacProvider::UnAdvise() { return S_OK; }

IFACEMETHODIMP CTacProvider::GetFieldDescriptorCount(DWORD* pdwCount)
{
    if (!pdwCount)
        return E_POINTER;
    *pdwCount = TFI_NUM_FIELDS;
    return S_OK;
}

IFACEMETHODIMP CTacProvider::GetFieldDescriptorAt(DWORD dwIndex,
                                                  CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    if (dwIndex >= TFI_NUM_FIELDS || !ppcpfd)
        return E_INVALIDARG;
    return FieldDescriptorCoAllocCopy(s_rgFieldDescriptors[dwIndex], ppcpfd);
}

IFACEMETHODIMP CTacProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault,
                                                BOOL* pbAutoLogonWithDefault)
{
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault)
        return E_POINTER;
    *pdwCount = 0;
    *pdwDefault = CREDENTIAL_PROVIDER_NO_DEFAULT;
    *pbAutoLogonWithDefault = FALSE;

    HRESULT hr = _CreateCredentials();
    if (FAILED(hr))
        return hr;
    *pdwCount = static_cast<DWORD>(_credentials.size());
    *pdwDefault = _defaultIndex;
    return S_OK;
}

IFACEMETHODIMP CTacProvider::GetCredentialAt(DWORD dwIndex,
                                             ICredentialProviderCredential** ppcpc)
{
    if (!ppcpc)
        return E_INVALIDARG;
    *ppcpc = nullptr;
    HRESULT hr = _CreateCredentials();
    if (FAILED(hr))
        return hr;
    if (dwIndex >= _credentials.size())
        return E_INVALIDARG;
    return _credentials[dwIndex]->QueryInterface(IID_PPV_ARGS(ppcpc));
}

// --- ICredentialProviderSetUserArray ----------------------------------------

IFACEMETHODIMP CTacProvider::SetUserArray(ICredentialProviderUserArray* users)
{
    if (_pUserArray)
        _pUserArray->Release();
    _pUserArray = users;
    if (_pUserArray)
        _pUserArray->AddRef();
    _built = false;
    return S_OK;
}

HRESULT CTacProvider_CreateInstance(REFIID riid, void** ppv)
{
    CTacProvider* provider = new (std::nothrow) CTacProvider();
    if (!provider)
        return E_OUTOFMEMORY;
    HRESULT hr = provider->QueryInterface(riid, ppv);
    provider->Release();
    return hr;
}
