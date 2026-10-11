// Stand-in for <ntsecapi.h>: the LSA types ap.cpp and subauth.cpp use.
#pragma once
#include "windows.h"

typedef struct _UNICODE_STRING
{
    USHORT Length;          // bytes, without a terminating NUL
    USHORT MaximumLength;   // bytes
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LSA_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PCHAR  Buffer;
} LSA_STRING, *PLSA_STRING;

typedef enum _SECURITY_LOGON_TYPE
{
    UndefinedLogonType = 0,
    Interactive = 2,
    Network,
    Batch,
    Service,
    Proxy,
    Unlock,
    NetworkCleartext,
    NewCredentials,
    RemoteInteractive,
    CachedInteractive,
    CachedRemoteInteractive,
    CachedUnlock
} SECURITY_LOGON_TYPE;

typedef enum _KERB_LOGON_SUBMIT_TYPE
{
    KerbInteractiveLogon = 2,
    KerbSmartCardLogon = 6,
    KerbWorkstationUnlockLogon = 7
} KERB_LOGON_SUBMIT_TYPE;

typedef struct _KERB_INTERACTIVE_LOGON
{
    KERB_LOGON_SUBMIT_TYPE MessageType;
    UNICODE_STRING         LogonDomainName;
    UNICODE_STRING         UserName;
    UNICODE_STRING         Password;
} KERB_INTERACTIVE_LOGON;

typedef struct _LUID { DWORD LowPart; LONG HighPart; } LUID, *PLUID;
