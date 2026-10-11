// Minimal stand-in for <windows.h>: just enough for totp.cpp, verify.cpp,
// store_index.cpp, ap.cpp, subauth.cpp and their headers to compile on Linux.
// Only used by the native tests. The functions declared at the bottom are
// defined by the fakes of the test that needs them (lsa_fakes.cpp).
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <strings.h>

typedef unsigned char  BYTE;
typedef unsigned char  UCHAR;
typedef UCHAR*         PUCHAR;
typedef unsigned long  ULONG;
typedef ULONG*         PULONG;
typedef uint32_t       DWORD;
typedef DWORD*         LPDWORD;
typedef BYTE*          LPBYTE;
typedef int32_t        LONG;
typedef long           NTSTATUS;
typedef NTSTATUS*      PNTSTATUS;
typedef void*          HANDLE;
typedef wchar_t        WCHAR;
typedef WCHAR*         PWSTR;
typedef WCHAR*         LPWSTR;
typedef const WCHAR*   LPCWSTR;
typedef char*          PCHAR;
typedef void*          PVOID;
typedef void*          LPVOID;
typedef void           VOID;
typedef size_t         SIZE_T;
typedef uintptr_t      ULONG_PTR;
typedef uint64_t       ULONGLONG;
typedef int64_t        LONGLONG;
typedef uint16_t       USHORT;
typedef uint16_t       WORD;
typedef unsigned char  BOOLEAN;
typedef BOOLEAN*       PBOOLEAN;
typedef int            BOOL;
typedef LONG           LSTATUS;
typedef DWORD          LCID;
typedef DWORD          REGSAM;
typedef void*          PSID;
typedef void*          BCRYPT_ALG_HANDLE;
typedef void*          BCRYPT_HASH_HANDLE;

struct HKEY__;
typedef HKEY__*        HKEY;
typedef HKEY*          PHKEY;
struct HINSTANCE__;
typedef HINSTANCE__*   HMODULE;

typedef union _LARGE_INTEGER { LONGLONG QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;

#define NTAPI
#define APIENTRY
#define TRUE  1
#define FALSE 0

#define INVALID_HANDLE_VALUE (reinterpret_cast<HANDLE>(-1))
#define HKEY_LOCAL_MACHINE   (reinterpret_cast<HKEY>(static_cast<ULONG_PTR>(0x80000002)))

#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))

#define ERROR_SUCCESS        0L
#define ERROR_FILE_NOT_FOUND 2L
#define ERROR_ACCESS_DENIED  5L
#define ERROR_OUTOFMEMORY    14L

#define KEY_QUERY_VALUE      0x0001

#define EVENTLOG_ERROR_TYPE       0x0001
#define EVENTLOG_WARNING_TYPE     0x0002
#define EVENTLOG_INFORMATION_TYPE 0x0004

#define LOCALE_INVARIANT 0x007F
#define LCMAP_LOWERCASE  0x00000100

#define DLL_PROCESS_ATTACH 1

#define EXCEPTION_STACK_OVERFLOW            0xC00000FDu
#define EXCEPTION_NONCONTINUABLE_EXCEPTION  0xC0000025u
#define EXCEPTION_EXECUTE_HANDLER           1
#define EXCEPTION_CONTINUE_SEARCH           0

// SEH does not exist in g++ on Linux. The tests map __try/__except to C++
// try/catch (...), and the fake registry throws to stand in for an access
// violation. libstdc++ defines __try the same way.
#ifndef __try
#define __try try
#endif
#define __except(filter) catch (...)

inline void SecureZeroMemory(void* p, size_t n)
{
    volatile unsigned char* v = static_cast<volatile unsigned char*>(p);
    while (n--) *v++ = 0;
}

// Defined by tests/native/lsa_fakes.cpp.
int     LCMapStringW(LCID, DWORD, LPCWSTR src, int cchSrc, LPWSTR dst, int cchDst);
LSTATUS RegOpenKeyExW(HKEY root, LPCWSTR path, DWORD, REGSAM, PHKEY out);
LSTATUS RegQueryValueExW(HKEY, LPCWSTR value, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
LSTATUS RegCloseKey(HKEY);
void    OutputDebugStringW(LPCWSTR text);
HANDLE  RegisterEventSourceW(LPCWSTR server, LPCWSTR source);
BOOL    ReportEventW(HANDLE, WORD type, WORD category, DWORD id, PSID, WORD count,
                     DWORD, LPCWSTR* strings, LPVOID);
BOOL    DeregisterEventSource(HANDLE);
BOOL    DisableThreadLibraryCalls(HMODULE);
