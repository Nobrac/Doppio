#pragma once
// A fake registry, event log and LSA heap, so the real ap.cpp, subauth.cpp and
// store_index.cpp can run on Linux. See lsa_fakes.cpp.
#include <windows.h>
#include <ntsecpkg.h>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace fake
{
    // Registry: key path (as the code passes it) -> value names present.
    extern std::map<std::wstring, std::set<std::wstring>> keys;

    // Failure injection.
    extern LSTATUS openStatus;     // returned by RegOpenKeyExW for keys that exist
    extern LSTATUS queryStatus;    // returned by RegQueryValueExW
    extern bool    throwOnOpen;    // stand-in for an access violation; thrown
                                   // before a handle exists, like a fault in
                                   // the caller's buffers would be
    extern bool    failLcMap;      // LCMapStringW returns 0
    extern int     allocBudget;    // LSA heap blocks left before AllocateLsaHeap
                                   // returns null; -1 = unlimited

    // What the code under test left behind.
    extern std::vector<std::wstring> debug;    // OutputDebugStringW lines
    extern std::vector<DWORD>        events;   // ReportEventW ids
    extern int opened, closed;                 // registry handles
    extern int lsaAllocs, lsaFrees;            // LSA heap blocks

    extern LSA_DISPATCH_TABLE lsa;

    // Clears everything above except the dispatch table.
    void Reset();

    bool DebugContains(const wchar_t* text);
}
