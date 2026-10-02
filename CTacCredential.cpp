#include "CTacCredential.h"
#include "helpers.h"
#include "guid.h"
#include "store.h"
#include "verify.h"
#include "eventlog.h"
#include "dll.h"

#include <ntsecapi.h>
#include <shlwapi.h>
#include <strsafe.h>
#include <cstdio>
#include <ctime>
#include <string>
#include <vector>

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

// STATUS_LOGON_FAILURE lives in ntstatus.h, which clashes with windows.h unless
// WIN32_NO_STATUS is set everywhere. Defining the one value we need is simpler.
#ifndef STATUS_LOGON_FAILURE
#define STATUS_LOGON_FAILURE ((NTSTATUS)0xC000006DL)
#endif

CTacCredential::CTacCredential()
    : _cRef(1), _cpus(CPUS_INVALID), _pszSid(nullptr), _pCredProvCredentialEvents(nullptr)
{
    ZeroMemory(_rgFieldDescriptors, sizeof(_rgFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
    DllAddRef();
}

CTacCredential::~CTacCredential()
{
    for (DWORD i = 0; i < TFI_NUM_FIELDS; ++i)
        _FreeField(i);
    CoTaskMemFree(_pszSid);
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->Release();
    DllRelease();
}

// Wipe and free a field string.
void CTacCredential::_FreeField(DWORD dwFieldID)
{
    PWSTR& s = _rgFieldStrings[dwFieldID];
    if (s)
    {
        size_t len = 0;
        if (SUCCEEDED(StringCchLengthW(s, STRSAFE_MAX_CCH, &len)))
            SecureZeroMemory(s, len * sizeof(WCHAR));
        CoTaskMemFree(s);
        s = nullptr;
    }
}

// Clear a field back to an empty string, both in our copy and on screen.
void CTacCredential::_ResetField(DWORD dwFieldID)
{
    _FreeField(dwFieldID);
    SHStrDupW(L"", &_rgFieldStrings[dwFieldID]);
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->SetFieldString(this, dwFieldID, L"");
}

HRESULT CTacCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                                   const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                                   const FIELD_STATE_PAIR* rgfsp,
                                   PCWSTR pwzUser, PCWSTR pwzPassword, PCWSTR pwzSid)
{
    _cpus = cpus;
    for (DWORD i = 0; i < TFI_NUM_FIELDS; ++i)
    {
        _rgFieldDescriptors[i] = rgcpfd[i];
        _rgFieldStatePairs[i]  = rgfsp[i];
    }

    const bool hasUser = pwzUser && *pwzUser;
    const bool hasPass = pwzPassword && *pwzPassword;

    // A tile without a SID is the fallback or RDP tile: it is not bound to an
    // account, so the username field is shown. Put the caret on the first empty
    // field.
    if (!pwzSid)
    {
        _rgFieldStatePairs[TFI_USERNAME] = { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE };
        _rgFieldStatePairs[TFI_PASSWORD].cpfis = CPFIS_NONE;
        if (!hasUser)
            _rgFieldStatePairs[TFI_USERNAME].cpfis = CPFIS_FOCUSED;
        else if (!hasPass)
            _rgFieldStatePairs[TFI_PASSWORD].cpfis = CPFIS_FOCUSED;
        else
            _rgFieldStatePairs[TFI_OTP].cpfis = CPFIS_FOCUSED;
    }

    HRESULT hr = pwzSid ? SHStrDupW(pwzSid, &_pszSid) : S_OK;
    if (SUCCEEDED(hr))
        hr = SHStrDupW(L"TheAdminCafe 2FA", &_rgFieldStrings[TFI_LABEL]);
    if (SUCCEEDED(hr))
        hr = SHStrDupW(hasUser ? pwzUser : L"", &_rgFieldStrings[TFI_USERNAME]);
    if (SUCCEEDED(hr))
        hr = SHStrDupW(hasPass ? pwzPassword : L"", &_rgFieldStrings[TFI_PASSWORD]);
    if (SUCCEEDED(hr))
        hr = SHStrDupW(L"", &_rgFieldStrings[TFI_OTP]);
    return hr;
}

// --- IUnknown ---------------------------------------------------------------

IFACEMETHODIMP_(ULONG) CTacCredential::AddRef()
{
    return InterlockedIncrement(&_cRef);
}

IFACEMETHODIMP_(ULONG) CTacCredential::Release()
{
    LONG cRef = InterlockedDecrement(&_cRef);
    if (cRef == 0)
        delete this;
    return cRef;
}

IFACEMETHODIMP CTacCredential::QueryInterface(REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    if (IsEqualIID(riid, IID_IUnknown) ||
        IsEqualIID(riid, __uuidof(ICredentialProviderCredential)) ||
        IsEqualIID(riid, __uuidof(ICredentialProviderCredential2)))
    {
        *ppv = static_cast<ICredentialProviderCredential2*>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

// --- ICredentialProviderCredential ------------------------------------------

IFACEMETHODIMP CTacCredential::Advise(ICredentialProviderCredentialEvents* pcpce)
{
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->Release();
    _pCredProvCredentialEvents = pcpce;
    if (_pCredProvCredentialEvents)
        _pCredProvCredentialEvents->AddRef();
    return S_OK;
}

IFACEMETHODIMP CTacCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
        _pCredProvCredentialEvents = nullptr;
    }
    return S_OK;
}

IFACEMETHODIMP CTacCredential::SetSelected(BOOL* pbAutoLogon)
{
    *pbAutoLogon = FALSE;   // we always need the code, so never log on automatically
    return S_OK;
}

IFACEMETHODIMP CTacCredential::SetDeselected()
{
    // Do not leave the password or the code in memory once the tile is left.
    _ResetField(TFI_PASSWORD);
    _ResetField(TFI_OTP);
    return S_OK;
}

IFACEMETHODIMP CTacCredential::GetFieldState(DWORD dwFieldID,
                                             CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                             CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis)
{
    if (dwFieldID >= TFI_NUM_FIELDS)
        return E_INVALIDARG;
    *pcpfs  = _rgFieldStatePairs[dwFieldID].cpfs;
    *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
    return S_OK;
}

IFACEMETHODIMP CTacCredential::GetStringValue(DWORD dwFieldID, PWSTR* ppwsz)
{
    if (dwFieldID >= TFI_NUM_FIELDS)
        return E_INVALIDARG;
    return SHStrDupW(_rgFieldStrings[dwFieldID] ? _rgFieldStrings[dwFieldID] : L"", ppwsz);
}

// The provider logo, drawn in code so no image file is required. A coffee-brown
// square with "2FA". This is only the small icon under "Sign-in options"; the
// large round picture on a user tile is the account picture drawn by Windows.
static HBITMAP CreateLogo()
{
    const int size = 128;

    BITMAPINFO bmi = {};
    bmi.bmiHeader.biSize     = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth    = size;
    bmi.bmiHeader.biHeight   = -size;   // top-down
    bmi.bmiHeader.biPlanes   = 1;
    bmi.bmiHeader.biBitCount = 24;      // no alpha channel to worry about
    bmi.bmiHeader.biCompression = BI_RGB;

    void* pvBits = nullptr;
    HBITMAP hbmp = CreateDIBSection(nullptr, &bmi, DIB_RGB_COLORS, &pvBits, nullptr, 0);
    if (!hbmp)
        return nullptr;

    HDC hdc = CreateCompatibleDC(nullptr);
    if (!hdc)
    {
        DeleteObject(hbmp);
        return nullptr;
    }

    HGDIOBJ hOldBmp = SelectObject(hdc, hbmp);

    RECT rc = { 0, 0, size, size };
    HBRUSH hBrush = CreateSolidBrush(RGB(0x6F, 0x4E, 0x37));
    FillRect(hdc, &rc, hBrush);
    DeleteObject(hBrush);

    HFONT hFont = CreateFontW(-48, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_SWISS, L"Segoe UI");
    HGDIOBJ hOldFont = hFont ? SelectObject(hdc, hFont) : nullptr;
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(0xFF, 0xFF, 0xFF));
    DrawTextW(hdc, L"2FA", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    if (hOldFont)
        SelectObject(hdc, hOldFont);
    if (hFont)
        DeleteObject(hFont);
    SelectObject(hdc, hOldBmp);
    DeleteDC(hdc);
    GdiFlush();
    return hbmp;
}

IFACEMETHODIMP CTacCredential::GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp)
{
    if (dwFieldID != TFI_TILEIMAGE || !phbmp)
        return E_INVALIDARG;

    HBITMAP hbmp = CreateLogo();
    if (!hbmp)
        return E_FAIL;

    *phbmp = hbmp;   // LogonUI takes ownership and deletes it
    return S_OK;
}

IFACEMETHODIMP CTacCredential::GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo)
{
    if (dwFieldID != TFI_SUBMIT || !pdwAdjacentTo)
        return E_INVALIDARG;
    *pdwAdjacentTo = TFI_OTP;   // the arrow sits next to the code field
    return S_OK;
}

IFACEMETHODIMP CTacCredential::SetStringValue(DWORD dwFieldID, PCWSTR pwz)
{
    if (dwFieldID != TFI_USERNAME && dwFieldID != TFI_PASSWORD && dwFieldID != TFI_OTP)
        return E_INVALIDARG;
    _FreeField(dwFieldID);
    return SHStrDupW(pwz ? pwz : L"", &_rgFieldStrings[dwFieldID]);
}

// Our tile has no checkbox or combo box fields.
IFACEMETHODIMP CTacCredential::GetCheckboxValue(DWORD, BOOL*, PWSTR*)       { return E_NOTIMPL; }
IFACEMETHODIMP CTacCredential::GetComboBoxValueCount(DWORD, DWORD*, DWORD*) { return E_NOTIMPL; }
IFACEMETHODIMP CTacCredential::GetComboBoxValueAt(DWORD, DWORD, PWSTR*)     { return E_NOTIMPL; }
IFACEMETHODIMP CTacCredential::SetCheckboxValue(DWORD, BOOL)                { return E_NOTIMPL; }
IFACEMETHODIMP CTacCredential::SetComboBoxSelectedValue(DWORD, DWORD)       { return E_NOTIMPL; }
IFACEMETHODIMP CTacCredential::CommandLinkClicked(DWORD)                    { return E_NOTIMPL; }

// --- ICredentialProviderCredential2 -----------------------------------------

// Returning a SID binds the tile to that account, so Windows shows its name and
// round picture. The fallback and RDP tiles have no SID and return S_FALSE,
// which makes them a generic tile with a username field.
IFACEMETHODIMP CTacCredential::GetUserSid(PWSTR* ppszSid)
{
    if (!ppszSid)
        return E_POINTER;
    *ppszSid = nullptr;
    if (!_pszSid)
        return S_FALSE;
    return SHStrDupW(_pszSid, ppszSid);
}

// --- the actual work: password, then code, then serialize -------------------

enum class PasswordCheck { Ok, Wrong, Refused };

// Asks Windows whether the password is right, before the code is looked at.
//
// The order matters. Every wrong code counts toward the lock, so if the code
// came first, anyone at the logon screen - or anyone with any RDP account,
// since the RDP tile lets you type another name - could lock every enrolled
// account out without knowing a single password. Checking the password first
// means only someone who already has factor one can burn guesses on factor
// two. Wrong passwords are counted by Windows itself (account lockout policy),
// exactly as on the built-in tile.
//
// LogonUser with LOGON32_LOGON_INTERACTIVE is used because the deny rights and
// the sub-authentication filter of this project block network logons for
// enrolled accounts. The token is closed right away; the side effect is one
// extra logon event (4624, type 2, process LogonUI.exe) per sign-in.
static PasswordCheck CheckPassword(PCWSTR domain, PCWSTR user, PCWSTR password, DWORD& error)
{
    error = ERROR_SUCCESS;
    HANDLE token = nullptr;
    if (LogonUserW(user, domain, password ? password : L"", LOGON32_LOGON_INTERACTIVE,
                   LOGON32_PROVIDER_DEFAULT, &token))
    {
        CloseHandle(token);
        return PasswordCheck::Ok;
    }

    error = GetLastError();
    switch (error)
    {
    // These are only reported after the password was accepted. The real logon
    // below runs into the same condition and Windows handles it there (for
    // example "Allow log on locally" missing for an RDP-only user on a server).
    case ERROR_LOGON_TYPE_NOT_GRANTED:
    case ERROR_PASSWORD_MUST_CHANGE:
    case ERROR_PASSWORD_EXPIRED:
        return PasswordCheck::Ok;

    case ERROR_LOGON_FAILURE:
        return PasswordCheck::Wrong;

    default:   // locked out, disabled, blank password not allowed, ...
        return PasswordCheck::Refused;
    }
}


IFACEMETHODIMP CTacCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    PWSTR* ppwszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
    pcpcs->rgbSerialization = nullptr;
    pcpcs->cbSerialization  = 0;

    // The username field holds "PC\user" on a user tile, or whatever was typed
    // on the fallback tile. We only ever use the bare name, so the account we
    // check the code for is the same local account we log on below.
    std::wstring bare = _rgFieldStrings[TFI_USERNAME] ? _rgFieldStrings[TFI_USERNAME] : L"";
    size_t slash = bare.find_last_of(L'\\');
    if (slash != std::wstring::npos)
        bare.erase(0, slash + 1);

    // --- which account is this? ---
    // The secret belongs to a SID. We resolve COMPUTERNAME\name exactly like
    // LSA will. On a user tile the result has to be the SID of the tile.
    std::wstring sid;
    bool known = bare.size() <= 256 && tac::ResolveLocalUserSid(bare, sid);
    if (known && _pszSid && _wcsicmp(sid.c_str(), _pszSid) != 0)
        known = false;

    // Typed names end up in the event log; keep a long one from flooding it.
    const std::wstring shown   = bare.size() > 64 ? bare.substr(0, 64) + L"..." : bare;
    const std::wstring who     = shown + L" (" + (known ? sid : std::wstring(L"unknown account")) + L")";
    const std::wstring session = tac::DescribeSession();

    WCHAR computer[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD cchComputer = ARRAYSIZE(computer);
    if (!GetComputerNameW(computer, &cchComputer))
        return HRESULT_FROM_WIN32(GetLastError());

    // --- the first factor: is the password right? ---
    DWORD pwError = ERROR_SUCCESS;
    PasswordCheck pw = known
        ? CheckPassword(computer, bare.c_str(), _rgFieldStrings[TFI_PASSWORD], pwError)
        : PasswordCheck::Wrong;

    if (pw != PasswordCheck::Ok)
    {
        // The code was not looked at and nothing was counted. An unknown
        // account gets the same message as a wrong password.
        tac::LogEvent(EVENTLOG_WARNING_TYPE, tac::EVT_PASSWORD_BAD,
                      L"Password refused for " + who + L" (error " + std::to_wstring(pwError) +
                          L"). The one-time code was not checked. " + session + L".");

        PCWSTR message = L"The user name or password is incorrect.";
        if (pw == PasswordCheck::Refused)
            message = (pwError == ERROR_ACCOUNT_LOCKED_OUT)
                ? L"This account is locked by Windows. Try again later."
                : L"Windows refused the logon for this account.";

        _ResetField(TFI_PASSWORD);
        _ResetField(TFI_OTP);
        SHStrDupW(message, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_OK;   // S_OK keeps the tile alive; a failing HRESULT would kill it
    }

    // --- the second factor ---
    std::wstring code = _rgFieldStrings[TFI_OTP] ? _rgFieldStrings[TFI_OTP] : L"";
    tac::OtpInfo info = {};
    tac::OtpResult result = tac::VerifyOtp(sid, code, static_cast<uint64_t>(time(nullptr)), info);
    if (!code.empty())
        SecureZeroMemory(&code[0], code.size() * sizeof(WCHAR));

    if (result != tac::OtpResult::Ok)
    {
        // "Not enrolled", "wrong" and "already used" look the same on screen.
        // Only the lock gets its own message, otherwise a locked user would
        // keep typing valid codes.
        PCWSTR message = L"Invalid one-time code.";
        wchar_t lockText[128];

        switch (result)
        {
        case tac::OtpResult::Wrong:
        case tac::OtpResult::Replayed:
            tac::LogEvent(EVENTLOG_WARNING_TYPE,
                          result == tac::OtpResult::Wrong ? tac::EVT_CODE_WRONG : tac::EVT_CODE_REPLAYED,
                          (result == tac::OtpResult::Wrong ? L"Wrong one-time code for "
                                                           : L"Already used one-time code for ") +
                              who + L" (password was correct). Wrong codes in a row: " +
                              std::to_wstring(info.failures) + L". " + session + L".");
            if (info.minutesLeft)
            {
                tac::LogEvent(EVENTLOG_ERROR_TYPE, tac::EVT_LOCK_STARTED,
                              L"Account " + who + L" locked for " + std::to_wstring(info.minutesLeft) +
                                  L" minutes after " + std::to_wstring(info.failures) +
                                  L" wrong codes in a row. " + session + L".");
                swprintf_s(lockText, L"Too many wrong codes. Try again in %u minutes.", info.minutesLeft);
                message = lockText;
            }
            break;

        case tac::OtpResult::LockedOut:
            tac::LogEvent(EVENTLOG_WARNING_TYPE, tac::EVT_LOCKED_OUT,
                          L"Logon attempt for locked account " + who + L", " +
                              std::to_wstring(info.minutesLeft) + L" minutes left. " + session + L".");
            swprintf_s(lockText, L"Too many wrong codes. Try again in %u minutes.", info.minutesLeft);
            message = lockText;
            break;

        case tac::OtpResult::NotEnrolled:
            tac::LogEvent(EVENTLOG_WARNING_TYPE, tac::EVT_NOT_ENROLLED,
                          L"Logon attempt for " + who + L", which is not enrolled. " + session + L".");
            break;

        default:
            tac::LogEvent(EVENTLOG_ERROR_TYPE, tac::EVT_ERROR,
                          L"Could not lock, read or write the 2FA state of " + who +
                              L". The logon was refused. " + session + L".");
            break;
        }

        // The password is proven, keep it; only the code has to be typed again.
        _ResetField(TFI_OTP);
        SHStrDupW(message, ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
        return S_OK;
    }

    tac::LogEvent(EVENTLOG_INFORMATION_TYPE, tac::EVT_CODE_OK,
                  L"Valid one-time code for " + who + L" (time step " + std::to_wstring(info.step) +
                      L"). The password goes to LSA now. " + session + L".");

    // --- the ordinary password logon, once both factors are valid ---
    PWSTR pwzPassword = nullptr;
    HRESULT hr = ProtectIfNecessaryAndCopyPassword(_rgFieldStrings[TFI_PASSWORD], _cpus, &pwzPassword);

    // Always log on as COMPUTERNAME\user. This is a local-account demo, so we
    // never authenticate a domain the user might have typed.
    std::wstring qualified = std::wstring(computer) + L"\\" + bare;

    WCHAR domain[64] = {};
    WCHAR user[256]  = {};
    if (SUCCEEDED(hr))
        hr = SplitDomainAndUsername(qualified.c_str(), domain, ARRAYSIZE(domain),
                                    user, ARRAYSIZE(user));

    // Zeroed here and not only inside KerbInteractiveUnlockLogonInit: every use
    // below sits behind SUCCEEDED(hr), so today it can never be read uninitialised.
    // One edit that moves a call out of that chain would hand Pack a stack full
    // of garbage pointers, and this costs nothing.
    KERB_INTERACTIVE_UNLOCK_LOGON kiul = {};
    if (SUCCEEDED(hr))
        hr = KerbInteractiveUnlockLogonInit(domain, user, pwzPassword, _cpus, &kiul);
    if (SUCCEEDED(hr))
        hr = KerbInteractiveUnlockLogonPack(kiul, &pcpcs->rgbSerialization, &pcpcs->cbSerialization);
    if (SUCCEEDED(hr))
    {
        ULONG ulAuthPackage = 0;
        hr = RetrieveNegotiateAuthPackage(&ulAuthPackage);
        if (SUCCEEDED(hr))
        {
            pcpcs->ulAuthenticationPackage = ulAuthPackage;
            pcpcs->clsidCredentialProvider = CLSID_CTacProvider;
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
    }

    if (FAILED(hr) && pcpcs->rgbSerialization)
    {
        SecureZeroMemory(pcpcs->rgbSerialization, pcpcs->cbSerialization);
        CoTaskMemFree(pcpcs->rgbSerialization);
        pcpcs->rgbSerialization = nullptr;
        pcpcs->cbSerialization  = 0;
    }
    if (pwzPassword)
    {
        SecureZeroMemory(pwzPassword, wcslen(pwzPassword) * sizeof(WCHAR));
        CoTaskMemFree(pwzPassword);
    }
    return hr;
}

// LSA reports the result of the logon here. If it failed, clear password and
// code like the built-in tile does (the code is used up anyway). The password
// was already checked before the code, so a failure here is rare (the password
// was changed in between, or a logon right is missing).
IFACEMETHODIMP CTacCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS,
                                            PWSTR* ppwszOptionalStatusText,
                                            CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon)
{
    *ppwszOptionalStatusText = nullptr;
    *pcpsiOptionalStatusIcon = CPSI_NONE;

    if (ntsStatus != 0)
    {
        _ResetField(TFI_PASSWORD);
        _ResetField(TFI_OTP);
    }

    if (ntsStatus == STATUS_LOGON_FAILURE)
    {
        SHStrDupW(L"Incorrect password.", ppwszOptionalStatusText);
        *pcpsiOptionalStatusIcon = CPSI_ERROR;
    }
    return S_OK;
}
