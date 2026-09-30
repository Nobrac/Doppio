#include "totp.h"
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

namespace tac
{
    static const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    static int Base32Value(char c)
    {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a';
        if (c >= '2' && c <= '7') return c - '2' + 26;
        return -1;
    }

    bool Base32Decode(const std::string& in, std::vector<BYTE>& out)
    {
        uint32_t buffer = 0;
        int bits = 0;
        out.clear();

        for (char c : in)
        {
            if (c == '=' || c == ' ')
                continue;
            int v = Base32Value(c);
            if (v < 0)
                return false;

            buffer = (buffer << 5) | static_cast<uint32_t>(v);
            bits += 5;
            if (bits >= 8)
            {
                bits -= 8;
                out.push_back(static_cast<BYTE>(buffer >> bits));
                buffer &= (1u << bits) - 1;   // keep only the bits not consumed yet
            }
        }
        return true;
    }

    std::string Base32Encode(const BYTE* data, size_t len)
    {
        std::string out;
        uint32_t buffer = 0;
        int bits = 0;

        for (size_t i = 0; i < len; ++i)
        {
            buffer = (buffer << 8) | data[i];
            bits += 8;
            while (bits >= 5)
            {
                bits -= 5;
                out += kAlphabet[(buffer >> bits) & 0x1F];
            }
            buffer &= (1u << bits) - 1;
        }
        if (bits > 0)
            out += kAlphabet[(buffer << (5 - bits)) & 0x1F];
        return out;
    }

    static bool HmacSha1(const std::vector<BYTE>& key, const BYTE* msg, ULONG cbMsg, BYTE mac[20])
    {
        BCRYPT_ALG_HANDLE  hAlg  = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        bool ok = false;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr,
                                        BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return false;

        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, const_cast<PUCHAR>(key.data()),
                             static_cast<ULONG>(key.size()), 0) == 0)
        {
            ok = BCryptHashData(hHash, const_cast<PUCHAR>(msg), cbMsg, 0) == 0 &&
                 BCryptFinishHash(hHash, mac, 20, 0) == 0;
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return ok;
    }

    bool TotpAt(const std::vector<BYTE>& key, uint64_t unixTime,
                uint32_t step, int digits, uint32_t& code)
    {
        // The counter is the number of time steps since 1970, as 8 bytes big-endian.
        uint64_t counter = unixTime / step;
        BYTE msg[8];
        for (int i = 7; i >= 0; --i)
        {
            msg[i] = static_cast<BYTE>(counter & 0xFF);
            counter >>= 8;
        }

        BYTE mac[20];
        if (!HmacSha1(key, msg, sizeof(msg), mac))
            return false;

        // Dynamic truncation (RFC 4226, 5.3): the low nibble of the last byte
        // selects 4 bytes; the top bit is dropped to avoid signed values.
        int offset = mac[19] & 0x0F;
        uint32_t bin = ((mac[offset]     & 0x7Fu) << 24) |
                       ((mac[offset + 1] & 0xFFu) << 16) |
                       ((mac[offset + 2] & 0xFFu) <<  8) |
                        (mac[offset + 3] & 0xFFu);

        uint32_t mod = 1;
        for (int i = 0; i < digits; ++i)
            mod *= 10;
        code = bin % mod;
        return true;
    }

    bool ValidateTotp(const std::vector<BYTE>& key, const std::wstring& input,
                      uint64_t now, uint64_t lastStep, uint64_t& matchedStep,
                      uint32_t step, int digits, int window)
    {
        matchedStep = 0;

        // Exactly `digits` ASCII digits. wcstoul would also accept "12abc" or "0".
        if (input.size() != static_cast<size_t>(digits))
            return false;
        uint32_t entered = 0;
        for (wchar_t c : input)
        {
            if (c < L'0' || c > L'9')
                return false;
            entered = entered * 10 + static_cast<uint32_t>(c - L'0');
        }

        const uint64_t current = now / step;
        for (int w = -window; w <= window; ++w)
        {
            if (w < 0 && current < static_cast<uint64_t>(-w))
                continue;
            const uint64_t counter = current + static_cast<int64_t>(w);

            // "<=" and not "==": a step at or before the last used one is never
            // accepted again. This also stops an old code after the clock was
            // turned back.
            if (counter <= lastStep)
                continue;

            uint32_t expected = 0;
            if (TotpAt(key, counter * step, step, digits, expected) && expected == entered)
            {
                matchedStep = counter;
                return true;
            }
        }
        return false;
    }
}
