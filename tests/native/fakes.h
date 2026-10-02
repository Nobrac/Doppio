#pragma once
#include "store.h"
#include <map>

namespace tac
{
    extern std::map<std::wstring, std::vector<BYTE>> g_keys;
    extern std::map<std::wstring, UserState>         g_state;
    extern bool g_failSave;
    extern bool g_failLock;
    extern int  g_lockDepth;
    extern int  g_maxLockDepth;
    extern int  g_stateAccessOutsideLock;
}
