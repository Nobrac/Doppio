#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

namespace tac
{
    // After this many wrong codes in a row the account is locked.
    const uint32_t kFreeFailures = 5;

    enum class OtpResult
    {
        Ok,           // code correct, time step recorded
        Wrong,        // wrong code (counted)
        Replayed,     // correct code, but its time step was already used (counted)
        LockedOut,    // too many wrong codes, the code was not even checked
        NotEnrolled,  // no secret for this SID
        Error,        // state could not be read or written, fail closed
    };

    struct OtpInfo
    {
        uint32_t failures;      // wrong codes in a row, after this attempt
        uint32_t minutesLeft;   // lock time left, if locked
        uint64_t step;          // the accepted time step, if Ok
    };

    // Lock time after the n-th wrong code in a row: 0 up to kFreeFailures - 1,
    // then 5, 10, 20, 40 and at most 60 minutes.
    uint32_t LockMinutesFor(uint32_t failures);

    // Checks the code for the account and updates its state (replay
    // protection and rate limiting). `now` is the unix time. Holds the
    // StateLock for the whole load-check-save; if it cannot be taken, the
    // result is Error.
    //
    // Call this only AFTER the password was verified: every wrong code counts
    // toward the lock, so checking codes for a password nobody has proven would
    // let anyone at the logon screen lock any enrolled account out.
    OtpResult VerifyOtp(const std::wstring& sid, const std::wstring& code,
                        uint64_t now, OtpInfo& info);
}
