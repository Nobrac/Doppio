#pragma once
#include <windows.h>
#include <credentialprovider.h>
#include <shlguid.h>

// On a user tile Windows draws the account name and the round account picture
// itself. TFI_TILEIMAGE and TFI_LABEL are only the small logo and the name of
// our provider under "Sign-in options" (that is what the CPFG_ GUIDs mean).
enum TAC_FIELD_ID
{
    TFI_TILEIMAGE  = 0,
    TFI_LABEL      = 1,
    TFI_USERNAME   = 2,   // only visible on the fallback tile
    TFI_PASSWORD   = 3,
    TFI_OTP        = 4,
    TFI_SUBMIT     = 5,
    TFI_NUM_FIELDS = 6,
};

struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE             cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { TFI_TILEIMAGE, CPFT_TILE_IMAGE,    const_cast<PWSTR>(L"Image"), CPFG_CREDENTIAL_PROVIDER_LOGO },
    { TFI_LABEL,     CPFT_SMALL_TEXT,    const_cast<PWSTR>(L"TheAdminCafe 2FA"), CPFG_CREDENTIAL_PROVIDER_LABEL },
    { TFI_USERNAME,  CPFT_EDIT_TEXT,     const_cast<PWSTR>(L"Username") },
    { TFI_PASSWORD,  CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"Password") },
    { TFI_OTP,       CPFT_PASSWORD_TEXT, const_cast<PWSTR>(L"One-time code") },
    { TFI_SUBMIT,    CPFT_SUBMIT_BUTTON, const_cast<PWSTR>(L"Submit") },
};

// States for a user tile. CTacCredential::Initialize changes them for the
// fallback tile and the RDP tile.
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,          CPFIS_NONE    },   // TFI_TILEIMAGE
    { CPFS_HIDDEN,                   CPFIS_NONE    },   // TFI_LABEL
    { CPFS_HIDDEN,                   CPFIS_NONE    },   // TFI_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },   // TFI_PASSWORD
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },   // TFI_OTP
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE    },   // TFI_SUBMIT
};

// The provider reports TFI_NUM_FIELDS descriptors and LogonUI then asks for each
// one by index. If the enum and these tables ever drift apart, that is a read
// past the end of the array on the logon screen, so let the compiler check it.
static_assert(ARRAYSIZE(s_rgFieldDescriptors) == TFI_NUM_FIELDS,
              "s_rgFieldDescriptors must have one entry per TAC_FIELD_ID");
static_assert(ARRAYSIZE(s_rgFieldStatePairs) == TFI_NUM_FIELDS,
              "s_rgFieldStatePairs must have one entry per TAC_FIELD_ID");
