#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace tac
{
    // "PC\Alice", ".\alice" and "alice" all become "alice".
    std::wstring NormalizeUser(const std::wstring& user);

    // Looks up COMPUTERNAME\name and returns the SID string ("S-1-5-21-...")
    // if it is a local user account. Everything else returns false.
    bool ResolveLocalUserSid(const std::wstring& user, std::wstring& sid);

    // The secret is stored per SID, not per name. A renamed or re-created
    // account is a different account.
    bool StoreSecret(const std::wstring& sid, const std::string& base32Secret);
    bool LoadSecretKey(const std::wstring& sid, std::vector<BYTE>& key);

    // Per-account state for replay protection and rate limiting.
    struct UserState
    {
        uint64_t lastStep;      // last accepted TOTP time step, 0 = none yet
        uint32_t failures;      // wrong codes in a row
        uint32_t reserved;
        uint64_t lockedUntil;   // unix time, 0 = not locked
    };
    static_assert(sizeof(UserState) == 24, "UserState is stored as-is in the registry");

    // A missing value is a fresh state (all zero). A broken value is an error.
    bool LoadState(const std::wstring& sid, UserState& state);
    bool SaveState(const std::wstring& sid, const UserState& state);
    bool DeleteState(const std::wstring& sid);
}
