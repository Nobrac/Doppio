// In-memory replacements for the registry store and the state lock, so the
// real verify.cpp can run without Windows.
#include "store.h"
#include "statelock.h"
#include "fakes.h"

namespace tac
{
    std::map<std::wstring, std::vector<BYTE>> g_keys;
    std::map<std::wstring, UserState>         g_state;
    bool g_failSave = false;
    bool g_failLock = false;
    int  g_lockDepth = 0;
    int  g_maxLockDepth = 0;
    int  g_stateAccessOutsideLock = 0;

    bool LoadSecretKey(const std::wstring& sid, std::vector<BYTE>& key)
    {
        auto it = g_keys.find(sid);
        if (it == g_keys.end()) return false;
        key = it->second;
        return true;
    }

    bool LoadState(const std::wstring& sid, UserState& s)
    {
        if (g_lockDepth == 0) ++g_stateAccessOutsideLock;
        auto it = g_state.find(sid);
        s = (it == g_state.end()) ? UserState{} : it->second;
        return true;
    }

    bool SaveState(const std::wstring& sid, const UserState& s)
    {
        if (g_lockDepth == 0) ++g_stateAccessOutsideLock;
        if (g_failSave) return false;
        g_state[sid] = s;
        return true;
    }

    StateLock::StateLock(DWORD) : _h(INVALID_HANDLE_VALUE)
    {
        if (g_failLock) return;
        _h = reinterpret_cast<HANDLE>(1);
        if (++g_lockDepth > g_maxLockDepth) g_maxLockDepth = g_lockDepth;
    }

    StateLock::~StateLock()
    {
        if (_h != INVALID_HANDLE_VALUE) --g_lockDepth;
    }
}
