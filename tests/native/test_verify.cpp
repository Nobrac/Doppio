// Native tests for the real totp.cpp and verify.cpp. See README, "Tests".
#include "totp.h"
#include "verify.h"
#include "fakes.h"
#include <cstdio>

using namespace tac;

static int g_failed = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL  line %d: %s\n", __LINE__, #c); ++g_failed; } \
                      else std::printf("ok    %s\n", #c); } while (0)

static std::wstring Code(const std::vector<BYTE>& key, uint64_t t)
{
    uint32_t c = 0;
    TotpAt(key, t, 30, 6, c);
    wchar_t buf[8];
    std::swprintf(buf, 8, L"%06u", c);
    return buf;
}

int main()
{
    const char* ascii = "12345678901234567890";            // RFC 6238 appendix B
    const std::vector<BYTE> seed(ascii, ascii + 20);
    uint32_t c = 0;
    uint64_t m = 0;

    std::printf("-- RFC 6238 vectors (SHA1, 8 digits)\n");
    const struct { uint64_t t; uint32_t code; } vectors[] = {
        { 59, 94287082 }, { 1111111109, 7081804 }, { 1111111111, 14050471 },
        { 1234567890, 89005924 }, { 2000000000, 69279037 }, { 20000000000ull, 65353130 } };
    for (const auto& v : vectors)
    {
        TotpAt(seed, v.t, 30, 8, c);
        CHECK(c == v.code);
    }

    std::printf("-- Base32\n");
    std::vector<BYTE> decoded;
    CHECK(Base32Encode(seed.data(), seed.size()) == "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    CHECK(Base32Decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", decoded) && decoded == seed);
    CHECK(Base32Decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq", decoded) && decoded == seed);
    CHECK(!Base32Decode("GEZD1GNB", decoded));                  // '1' is not Base32

    std::printf("-- input validation\n");
    const uint64_t T = 1800000000;
    CHECK(!ValidateTotp(seed, L"", T, 0, m));
    CHECK(!ValidateTotp(seed, L"12345", T, 0, m));
    CHECK(!ValidateTotp(seed, L"12abc6", T, 0, m));
    CHECK(!ValidateTotp(seed, L"\xFF11\xFF12\xFF13\xFF14\xFF15\xFF16", T, 0, m));  // full-width digits
    CHECK(ValidateTotp(seed, Code(seed, 59), 59, 0, m) && m == 1);  // window near the epoch

    std::printf("-- replay window\n");
    CHECK(ValidateTotp(seed, Code(seed, T), T, 0, m) && m == T / 30);
    CHECK(!ValidateTotp(seed, Code(seed, T), T, T / 30, m));       // same step again
    CHECK(!ValidateTotp(seed, Code(seed, T - 30), T, T / 30, m));  // older step
    CHECK(ValidateTotp(seed, Code(seed, T + 30), T, T / 30, m) && m == T / 30 + 1);

    std::printf("-- VerifyOtp: lock ladder\n");
    const std::wstring sid = L"S-1-5-21-1-2-3-1001";
    g_keys[sid] = seed;
    OtpInfo info = {};
    const uint32_t ladder[] = { 0, 0, 0, 0, 5, 10, 20, 40, 60, 60 };
    for (uint32_t i = 0; i < 10; ++i)
    {
        g_state[sid].lockedUntil = 0;                              // as if the lock ran out
        OtpResult r = VerifyOtp(sid, L"000000", T, info);
        CHECK(r == OtpResult::Wrong && info.failures == i + 1 && info.minutesLeft == ladder[i]);
    }

    std::printf("-- VerifyOtp: locked, replay, success\n");
    g_state[sid].lockedUntil = T + 600;
    uint32_t before = g_state[sid].failures;
    CHECK(VerifyOtp(sid, Code(seed, T), T, info) == OtpResult::LockedOut);
    CHECK(g_state[sid].failures == before && info.minutesLeft == 10);  // not counted, not checked
    g_state[sid].lockedUntil = 0;
    CHECK(VerifyOtp(sid, Code(seed, T), T, info) == OtpResult::Ok && g_state[sid].failures == 0);
    CHECK(VerifyOtp(sid, Code(seed, T), T + 5, info) == OtpResult::Replayed && info.failures == 1);
    CHECK(VerifyOtp(sid, Code(seed, T + 60), T + 30, info) == OtpResult::Ok);
    CHECK(VerifyOtp(sid, Code(seed, T + 30), T + 30, info) == OtpResult::Replayed);
    CHECK(VerifyOtp(L"S-1-5-21-9-9-9-1002", L"123456", T, info) == OtpResult::NotEnrolled);

    std::printf("-- VerifyOtp: fail closed\n");
    g_state[sid] = {};
    g_failSave = true;
    CHECK(VerifyOtp(sid, Code(seed, T + 90), T + 90, info) == OtpResult::Error);  // step not saved
    g_failSave = false;
    g_failLock = true;
    CHECK(VerifyOtp(sid, Code(seed, T + 90), T + 90, info) == OtpResult::Error);  // no lock, no check
    CHECK(g_state[sid].lastStep == 0 && g_state[sid].failures == 0);
    g_failLock = false;

    std::printf("-- VerifyOtp: state only touched under the lock\n");
    CHECK(g_stateAccessOutsideLock == 0);
    CHECK(g_maxLockDepth == 1 && g_lockDepth == 0);

    std::printf("\n%s (%d failed)\n", g_failed ? "SOME CHECKS FAILED" : "ALL CHECKS PASS", g_failed);
    return g_failed ? 1 : 0;
}
