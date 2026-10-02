#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include "common.h"

// One tile. ICredentialProviderCredential2 adds GetUserSid, which binds the
// tile to an account. That is what makes Windows show the account's name and
// its round picture, like on the built-in tiles.
class CTacCredential : public ICredentialProviderCredential2
{
public:
    CTacCredential();

    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
                       const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* rgcpfd,
                       const FIELD_STATE_PAIR* rgfsp,
                       PCWSTR pwzUser, PCWSTR pwzPassword, PCWSTR pwzSid);

    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef();
    IFACEMETHODIMP_(ULONG) Release();
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce);
    IFACEMETHODIMP UnAdvise();
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon);
    IFACEMETHODIMP SetDeselected();
    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
                                 CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs,
                                 CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis);
    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, PWSTR* ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, HBITMAP* phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldID, BOOL* pbChecked, PWSTR* ppwszLabel);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldID, DWORD* pdwAdjacentTo);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, DWORD* pcItems, DWORD* pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, PWSTR* ppwszItem);
    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldID, BOOL bChecked);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                    PWSTR* ppwszOptionalStatusText,
                                    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus,
                                PWSTR* ppwszOptionalStatusText,
                                CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(PWSTR* ppszSid);

private:
    virtual ~CTacCredential();

    void _FreeField(DWORD dwFieldID);
    void _ResetField(DWORD dwFieldID);

    // The body of GetSerialization. May throw std::bad_alloc; GetSerialization
    // catches it, so no C++ exception ever reaches LogonUI.
    HRESULT _GetSerializationImpl(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
                                  CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
                                  PWSTR* ppwszOptionalStatusText,
                                  CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiOptionalStatusIcon);

    LONG                                 _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO   _cpus;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR _rgFieldDescriptors[TFI_NUM_FIELDS];
    FIELD_STATE_PAIR                     _rgFieldStatePairs[TFI_NUM_FIELDS];
    PWSTR                                _rgFieldStrings[TFI_NUM_FIELDS];
    PWSTR                                _pszSid;   // null on the fallback and RDP tile
    ICredentialProviderCredentialEvents* _pCredProvCredentialEvents;
};
