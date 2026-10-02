// HMAC-SHA1 through OpenSSL, behind the handful of BCrypt calls totp.cpp makes.
#pragma once
#include <openssl/hmac.h>
#include <vector>

#define BCRYPT_SHA1_ALGORITHM       L"SHA1"
#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x8

struct ShimHash { std::vector<unsigned char> key, msg; };

inline NTSTATUS BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE* h, const wchar_t*, const wchar_t*, ULONG)
{ *h = reinterpret_cast<void*>(1); return 0; }
inline NTSTATUS BCryptCreateHash(BCRYPT_ALG_HANDLE, BCRYPT_HASH_HANDLE* h, PUCHAR, ULONG, PUCHAR k, ULONG cb, ULONG)
{ auto* s = new ShimHash; s->key.assign(k, k + cb); *h = s; return 0; }
inline NTSTATUS BCryptHashData(BCRYPT_HASH_HANDLE h, PUCHAR m, ULONG cb, ULONG)
{ auto* s = static_cast<ShimHash*>(h); s->msg.insert(s->msg.end(), m, m + cb); return 0; }
inline NTSTATUS BCryptFinishHash(BCRYPT_HASH_HANDLE h, PUCHAR out, ULONG, ULONG)
{
    auto* s = static_cast<ShimHash*>(h);
    unsigned int len = 20;
    return HMAC(EVP_sha1(), s->key.data(), static_cast<int>(s->key.size()),
                s->msg.data(), s->msg.size(), out, &len) ? 0 : -1;
}
inline NTSTATUS BCryptDestroyHash(BCRYPT_HASH_HANDLE h) { delete static_cast<ShimHash*>(h); return 0; }
inline NTSTATUS BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG) { return 0; }
