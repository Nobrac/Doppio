// Stand-in for the SDK's <subauth.h>: what Msv1_0SubAuthenticationFilter's
// signature and subauth.cpp use.
#pragma once
#include "ntsecapi.h"

typedef enum _NETLOGON_LOGON_INFO_CLASS
{
    NetlogonInteractiveInformation = 1,
    NetlogonNetworkInformation,
    NetlogonServiceInformation,
    NetlogonGenericInformation,
    NetlogonInteractiveTransitiveInformation,
    NetlogonNetworkTransitiveInformation,
    NetlogonServiceTransitiveInformation
} NETLOGON_LOGON_INFO_CLASS;

// The real structure is much larger; the filter reads only these two members,
// and the test builds them directly.
typedef struct _USER_ALL_INFORMATION
{
    UNICODE_STRING UserName;
    ULONG          UserId;
} USER_ALL_INFORMATION, *PUSER_ALL_INFORMATION;

#define MSV1_0_PASSTHRU    0x01
#define MSV1_0_GUEST_LOGON 0x02
