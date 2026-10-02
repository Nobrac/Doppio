// Minimal stand-in for <windows.h>: just enough for totp.cpp, verify.cpp and
// statelock.h to compile on Linux. Only used by the native tests.
#pragma once
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <strings.h>

typedef unsigned char  BYTE;
typedef unsigned char  UCHAR;
typedef UCHAR*         PUCHAR;
typedef unsigned long  ULONG;
typedef uint32_t       DWORD;
typedef long           NTSTATUS;
typedef void*          HANDLE;
typedef const wchar_t* LPCWSTR;
typedef void*          BCRYPT_ALG_HANDLE;
typedef void*          BCRYPT_HASH_HANDLE;

#define INVALID_HANDLE_VALUE (reinterpret_cast<HANDLE>(-1))

inline void SecureZeroMemory(void* p, size_t n)
{
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}
