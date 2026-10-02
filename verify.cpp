#include "verify.h"
#include "store.h"
#include "totp.h"
#include "statelock.h"
#include <vector>

namespace tac
{
    uint32_t LockMinutesFor(uint32_t failures)
    {
        if (failures < kFreeFailures)
            return 0;
        uint32_t doublings = failures - kFreeFailures;   // 0, 1, 2, ...
        if (doublings > 4)
            doublings = 4;                               // 5 << 4 = 80, capped below
        uint32_t minutes = 5u << doublings;
        return minutes > 60 ? 60 : minutes;
    }

    static uint32_t MinutesLeft(uint64_t lockedUntil, uint64_t now)
    {
        uint64_t seconds = lockedUntil > now ? lockedUntil - now : 0;
        return static_cast<uint32_t>((seconds + 59) / 60);   // round up
    }

    OtpResult VerifyOtp(const std::wstring& sid, const std::wstring& code,
                        uint64_t now, OtpInfo& info)
    {
        info = {};

        // Load, check and save as one step. Two logon screens checking the same
        // account at the same moment would otherwise both accept one code.
        // No lock, no check: fail closed.
        StateLock lock;
        if (!lock.Held())
            return OtpResult::Error;

        std::vector<BYTE> key;
        if (!LoadSecretKey(sid, key))
            return OtpResult::NotEnrolled;

        UserState state;
        if (!LoadState(sid, state))
        {
            SecureZeroMemory(key.data(), key.size());
            return OtpResult::Error;
        }
        info.failures = state.failures;

        // While the account is locked, the code is not checked at all.
        // Otherwise the lock would only hide the result, not stop the guessing.
        if (state.lockedUntil > now)
        {
            SecureZeroMemory(key.data(), key.size());
            info.minutesLeft = MinutesLeft(state.lockedUntil, now);
            return OtpResult::LockedOut;
        }

        uint64_t matched = 0;
        bool ok = ValidateTotp(key, code, now, state.lastStep, matched);

        // Only to write the right event: was it a correct code that was
        // already used? It still counts as a failure.
        uint64_t ignored = 0;
        bool replayed = !ok && state.lastStep != 0 && ValidateTotp(key, code, now, 0, ignored);
        SecureZeroMemory(key.data(), key.size());

        if (ok)
        {
            state.lastStep    = matched;
            state.failures    = 0;
            state.lockedUntil = 0;
            info.step         = matched;

            // If the step cannot be saved, the same code would work again.
            // So this is an error and not a success.
            return SaveState(sid, state) ? OtpResult::Ok : OtpResult::Error;
        }

        if (state.failures < 0xFFFFFFFFu)
            ++state.failures;
        uint32_t minutes = LockMinutesFor(state.failures);
        state.lockedUntil = minutes ? now + static_cast<uint64_t>(minutes) * 60 : 0;

        info.failures    = state.failures;
        info.minutesLeft = minutes;

        if (!SaveState(sid, state))
            return OtpResult::Error;
        return replayed ? OtpResult::Replayed : OtpResult::Wrong;
    }
}
