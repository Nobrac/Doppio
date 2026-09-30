#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace tac
{
    bool        Base32Decode(const std::string& in, std::vector<BYTE>& out);
    std::string Base32Encode(const BYTE* data, size_t len);

    // RFC 6238 code for a given unix time. Returns false if the HMAC fails.
    bool TotpAt(const std::vector<BYTE>& key, uint64_t unixTime,
                uint32_t step, int digits, uint32_t& code);

    // Accepts the time step of `now` and +/- window steps around it, but only
    // steps greater than lastStep (replay protection, 0 = nothing used yet).
    // On success matchedStep is the step the code belongs to.
    bool ValidateTotp(const std::vector<BYTE>& key, const std::wstring& input,
                      uint64_t now, uint64_t lastStep, uint64_t& matchedStep,
                      uint32_t step = 30, int digits = 6, int window = 1);
}
