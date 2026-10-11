#pragma once
// Registry layout of the 2FA store. Internal to store.cpp and store_index.cpp.
#include <windows.h>

namespace tac
{
    namespace keys
    {
        // Secrets: one REG_BINARY value per SID, DPAPI-protected.
        static const wchar_t kSecrets[] = L"SOFTWARE\\TheAdminCafe\\2FA";
        // Replay and lockout state: one UserState per SID.
        static const wchar_t kState[]   = L"SOFTWARE\\TheAdminCafe\\2FA\\State";
        // Enrollment indexes for the LSA hot path (presence only, no secret).
        static const wchar_t kNames[]   = L"SOFTWARE\\TheAdminCafe\\2FA\\Names";
        static const wchar_t kRids[]    = L"SOFTWARE\\TheAdminCafe\\2FA\\Rids";

        // UNLEN + 1. Nothing the SAM stores comes close.
        static const SIZE_T kMaxNameCch = 257;
    }
}
