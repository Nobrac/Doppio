#pragma once
#include <windows.h>

namespace tac
{
    // Serializes every read-modify-write of the per-account state across
    // processes. Without it, two LogonUI instances (two RDP sessions, or the
    // console and an RDP session) can both read the same state, both accept
    // the same code, and both get a full set of guesses per lock period.
    //
    // The lock is an exclusively opened file next to the module (normally
    // C:\Program Files\TheAdminCafe\state.lock). A named mutex would be simpler,
    // but any logged-on user can create a mutex under Global\ first and hold it,
    // which would block every 2FA logon on the machine. The install folder is
    // writable only by administrators, and the file is created with an ACL for
    // SYSTEM and Administrators only, so nobody else can open, let alone hold it.
    //
    // The OS closes the handle when a process dies, so a crash never leaves a
    // stale lock behind.
    class StateLock
    {
    public:
        explicit StateLock(DWORD timeoutMs = 5000);
        ~StateLock();

        bool Held() const { return _h != INVALID_HANDLE_VALUE; }

        StateLock(const StateLock&) = delete;
        StateLock& operator=(const StateLock&) = delete;

    private:
        HANDLE _h;
    };
}
