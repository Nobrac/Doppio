// Stand-in for <ntsecpkg.h>: the dispatch table and the opaque types in the
// authentication package's export signatures.
#pragma once
#include "ntsecapi.h"

typedef PVOID* PLSA_CLIENT_REQUEST;

// The real table has many more members; ap.cpp only uses these two.
typedef struct _LSA_DISPATCH_TABLE
{
    PVOID (NTAPI *AllocateLsaHeap)(ULONG Length);
    VOID  (NTAPI *FreeLsaHeap)(PVOID Base);
} LSA_DISPATCH_TABLE, *PLSA_DISPATCH_TABLE;

typedef enum _LSA_TOKEN_INFORMATION_TYPE { LsaTokenInformationNull } LSA_TOKEN_INFORMATION_TYPE,
                                                                     *PLSA_TOKEN_INFORMATION_TYPE;

struct _SECPKG_PRIMARY_CRED;
typedef struct _SECPKG_PRIMARY_CRED* PSECPKG_PRIMARY_CRED;
struct _SECPKG_SUPPLEMENTAL_CRED_ARRAY;
typedef struct _SECPKG_SUPPLEMENTAL_CRED_ARRAY* PSECPKG_SUPPLEMENTAL_CRED_ARRAY;
