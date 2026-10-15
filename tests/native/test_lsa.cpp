// Native tests for the code that runs inside lsass: the real subauth.cpp,
// ap.cpp and store_index.cpp, against a fake registry, event log and LSA heap
// (lsa_fakes.cpp). Built with AddressSanitizer and UBSan. See README, "Tests".
//
// What this cannot show: how MSV1_0 and LSA really call these exports, and
// real SEH. __try/__except are mapped to try/catch here, and the fake
// registry throws to stand in for an access violation. It throws before a key
// is opened: between RegOpenKeyExW and RegCloseKey the real code touches no
// pointer of the caller's, so that is not where a fault would come from.
#include "ap.h"
#include "subauth_filter.h"
#include "store.h"
#include "lsa_fakes.h"
#include <clocale>
#include <cstdio>
#include <string>
#include <vector>

static int g_failed = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL  line %d: %s\n", __LINE__, #c); ++g_failed; } \
                      else std::printf("ok    %s\n", #c); } while (0)

static const NTSTATUS kSuccess          = 0x00000000L;
static const NTSTATUS kAccountRestrict  = 0xC000006EL;
static const NTSTATUS kInvalidWorkst    = 0xC0000070L;
static const NTSTATUS kInvalidLogonType = 0xC000010BL;
static const NTSTATUS kNoMemory         = 0xC0000017L;

static const wchar_t kRids[]  = L"SOFTWARE\\TheAdminCafe\\2FA\\Rids";
static const wchar_t kNames[] = L"SOFTWARE\\TheAdminCafe\\2FA\\Names";

// ---- the sub-authentication filter -----------------------------------------

struct FilterResult
{
    NTSTATUS status;
    ULONG    which;
    ULONG    userFlags;
    BOOLEAN  authoritative;
    LONGLONG logoff;
    LONGLONG kickoff;
};

static FilterResult Filter(NETLOGON_LOGON_INFO_CLASS level, ULONG flags, ULONG rid,
                           std::wstring name, bool noUser = false)
{
    USER_ALL_INFORMATION ua = {};
    ua.UserId = rid;
    ua.UserName.Buffer        = name.empty() ? nullptr : &name[0];
    ua.UserName.Length        = static_cast<USHORT>(name.size() * sizeof(WCHAR));
    ua.UserName.MaximumLength = ua.UserName.Length;

    ULONG which = 0xFFFF, userFlags = 0xFFFF;
    BOOLEAN authoritative = 2;
    LARGE_INTEGER logoff, kickoff;
    logoff.QuadPart  = 111;
    kickoff.QuadPart = 222;

    NTSTATUS s = Msv1_0SubAuthenticationFilter(level, nullptr, flags, noUser ? nullptr : &ua,
                                               &which, &userFlags, &authoritative,
                                               &logoff, &kickoff);
    return { s, which, userFlags, authoritative, logoff.QuadPart, kickoff.QuadPart };
}

// The outputs the documentation calls [out] are valid on every path, and the
// logon hours MSV1_0 handed in are left alone.
static bool OutputsSane(const FilterResult& r)
{
    return r.which == 0 && r.userFlags == 0 && r.authoritative == TRUE &&
           r.logoff == 111 && r.kickoff == 222;
}

static void TestFilter()
{
    std::printf("-- sub-auth filter: decisions\n");
    fake::Reset();
    fake::keys[kRids] = { L"1001", L"4294967295" };

    FilterResult r = Filter(NetlogonInteractiveInformation, 0, 1001, L"alice");
    CHECK(r.status == kSuccess && OutputsSane(r));               // not network: no objection
    CHECK(fake::events.empty());

    r = Filter(NetlogonNetworkInformation, 0, 1002, L"bob");
    CHECK(r.status == kSuccess && OutputsSane(r));               // network, not enrolled
    CHECK(fake::events.empty());

    r = Filter(NetlogonNetworkInformation, 0, 1001, L"alice");
    CHECK(r.status == kInvalidWorkst && OutputsSane(r));         // network, enrolled
    CHECK(fake::events.size() == 1 && fake::events[0] == 210);

    r = Filter(NetlogonNetworkTransitiveInformation, 0, 1001, L"alice");
    CHECK(r.status == kInvalidWorkst && OutputsSane(r));

    r = Filter(NetlogonNetworkInformation, 0, 4294967295u, L"max");
    CHECK(r.status == kInvalidWorkst);                            // 10-digit RID value name

    r = Filter(NetlogonNetworkInformation, 0, 0, L"rid0");
    CHECK(r.status == kSuccess);                                  // RID 0 is never enrolled

    std::printf("-- sub-auth filter: pass-through and missing record\n");
    r = Filter(NetlogonNetworkInformation, MSV1_0_PASSTHRU, 1001, L"alice");
    CHECK(r.status == kSuccess && OutputsSane(r));               // not our account
    CHECK(fake::DebugContains(L"pass-through"));

    r = Filter(NetlogonNetworkInformation, 0, 1001, L"", true);
    CHECK(r.status == kInvalidWorkst && OutputsSane(r));         // no SAM record: refuse
    CHECK(fake::DebugContains(L"no SAM record"));
    r = Filter(NetlogonInteractiveInformation, 0, 1001, L"", true);
    CHECK(r.status == kSuccess && OutputsSane(r));               // ...but only on the network
    r = Filter(NetlogonNetworkInformation, MSV1_0_PASSTHRU, 1001, L"", true);
    CHECK(r.status == kSuccess && OutputsSane(r));               // ...to this machine

    std::printf("-- sub-auth filter: fail closed\n");
    fake::keys.erase(kRids);
    r = Filter(NetlogonNetworkInformation, 0, 1001, L"alice");
    CHECK(r.status == kSuccess);                                  // no index at all = No

    fake::keys[kRids] = { L"1001" };
    fake::openStatus = ERROR_ACCESS_DENIED;
    r = Filter(NetlogonNetworkInformation, 0, 1002, L"bob");
    CHECK(r.status == kInvalidWorkst && OutputsSane(r));         // unreadable = refuse
    CHECK(fake::DebugContains(L"could not be read"));
    fake::openStatus = ERROR_SUCCESS;

    fake::queryStatus = ERROR_OUTOFMEMORY;
    r = Filter(NetlogonNetworkInformation, 0, 1002, L"bob");
    CHECK(r.status == kInvalidWorkst);
    fake::queryStatus = ERROR_SUCCESS;

    fake::throwOnOpen = true;
    r = Filter(NetlogonNetworkInformation, 0, 1002, L"bob");
    CHECK(r.status == kInvalidWorkst && OutputsSane(r));         // fault on network: refuse
    CHECK(fake::DebugContains(L"Exception while deciding"));
    r = Filter(NetlogonInteractiveInformation, 0, 1002, L"bob");
    CHECK(r.status == kSuccess);                                  // no read, no fault
    fake::throwOnOpen = false;

    std::printf("-- sub-auth filter: logging\n");
    fake::debug.clear();
    Filter(NetlogonNetworkInformation, 0, 1002, std::wstring(L"ev\0il", 5));
    CHECK(fake::DebugContains(L"'ev'") && !fake::DebugContains(L"il'"));  // stops at NUL
    Filter(NetlogonNetworkInformation, 0, 1002, std::wstring(L"a\x01" L"b"));
    CHECK(fake::DebugContains(L"'a.b'"));                         // control char masked
    CHECK(fake::DebugContains(L"incoming LogoffTime=111 KickoffTime=222"));
    Filter(NetlogonNetworkInformation, 0, 1002, std::wstring(400, L'x'));
    CHECK(!fake::debug.empty() && fake::debug.back().size() < 352);  // cut, not overflowed

    // Null out-parameters must not crash.
    USER_ALL_INFORMATION ua = {};
    ua.UserId = 1001;
    CHECK(Msv1_0SubAuthenticationFilter(NetlogonNetworkInformation, nullptr, 0, &ua, nullptr,
                                        nullptr, nullptr, nullptr, nullptr) == kInvalidWorkst);

    CHECK(fake::opened == fake::closed);
}

// ---- the authentication package --------------------------------------------

static const ULONG_PTR kClientBase = 0x7ff000000000ull;

// A KERB_INTERACTIVE_LOGON with the user name behind it, the name either as a
// client-process address (relative to kClientBase) or as a packed offset.
static std::vector<BYTE> Submit(const std::wstring& user, bool packed,
                                KERB_LOGON_SUBMIT_TYPE type = KerbInteractiveLogon)
{
    const size_t off = sizeof(KERB_INTERACTIVE_LOGON);
    std::vector<BYTE> b(off + user.size() * sizeof(WCHAR));
    auto* k = reinterpret_cast<KERB_INTERACTIVE_LOGON*>(b.data());
    k->MessageType = type;
    if (!user.empty())
        std::memcpy(b.data() + off, user.data(), user.size() * sizeof(WCHAR));
    k->UserName.Length        = static_cast<USHORT>(user.size() * sizeof(WCHAR));
    k->UserName.MaximumLength = k->UserName.Length;
    k->UserName.Buffer        = reinterpret_cast<PWSTR>(packed ? off : kClientBase + off);
    return b;
}

struct ApResult
{
    NTSTATUS     status;
    NTSTATUS     sub;
    bool         haveAccount;
    std::wstring account;
};

static ApResult Logon(SECURITY_LOGON_TYPE type, std::vector<BYTE> submit, bool wantAccount = true)
{
    PVOID profile = reinterpret_cast<PVOID>(1);
    ULONG profileSize = 99;
    LUID luid = {};
    NTSTATUS sub = 12345;
    LSA_TOKEN_INFORMATION_TYPE tokenType = LsaTokenInformationNull;
    PVOID token = nullptr;
    PUNICODE_STRING account   = nullptr;
    PUNICODE_STRING authority = reinterpret_cast<PUNICODE_STRING>(1);
    PUNICODE_STRING machine   = reinterpret_cast<PUNICODE_STRING>(1);
    PSECPKG_SUPPLEMENTAL_CRED_ARRAY cached = reinterpret_cast<PSECPKG_SUPPLEMENTAL_CRED_ARRAY>(1);

    NTSTATUS s = LsaApLogonUserEx2(nullptr, type,
                                   submit.empty() ? nullptr : submit.data(),
                                   reinterpret_cast<PVOID>(kClientBase),
                                   static_cast<ULONG>(submit.size()),
                                   &profile, &profileSize, &luid, &sub, &tokenType, &token,
                                   wantAccount ? &account : nullptr,
                                   &authority, &machine, nullptr, &cached);

    CHECK(profile == nullptr && profileSize == 0 && authority == nullptr &&
          machine == nullptr && cached == nullptr);

    ApResult r = { s, sub, account != nullptr, L"" };
    if (account)
    {
        const size_t cch = account->Length / sizeof(WCHAR);
        CHECK(account->MaximumLength == account->Length + sizeof(WCHAR) &&
              account->Buffer[cch] == L'\0');
        r.account.assign(account->Buffer, cch);
        fake::lsa.FreeLsaHeap(account->Buffer);       // as LSA would
        fake::lsa.FreeLsaHeap(account);
    }
    return r;
}

static void TestAuthPackage()
{
    std::printf("-- authentication package: initialize\n");
    fake::Reset();
    PLSA_STRING name = reinterpret_cast<PLSA_STRING>(1);

    fake::allocBudget = 1;                                         // second block fails
    CHECK(LsaApInitializePackage(7, &fake::lsa, nullptr, nullptr, &name) == kNoMemory);
    CHECK(name == nullptr && fake::lsaAllocs == fake::lsaFrees);   // first block given back

    fake::allocBudget = -1;
    CHECK(LsaApInitializePackage(7, &fake::lsa, nullptr, nullptr, &name) == kSuccess);
    CHECK(name && name->Length == 14 && std::strcmp(name->Buffer, "TacAuthPackage") == 0);
    CHECK(fake::DebugContains(L"[Doppio-AP] LSA authentication package loaded (id 7)."));
    fake::lsa.FreeLsaHeap(name->Buffer);
    fake::lsa.FreeLsaHeap(name);

    std::printf("-- authentication package: decisions\n");
    fake::keys[kNames] = { L"alice", L"jörg" };

    ApResult r = Logon(Network, Submit(L"alice", false));
    CHECK(r.status == kAccountRestrict && r.sub == kInvalidWorkst);   // enrolled, network
    CHECK(r.account == L"alice");
    CHECK(!fake::events.empty() && fake::events.back() == 201);

    r = Logon(Network, Submit(L"alice", true));                       // packed offsets
    CHECK(r.status == kAccountRestrict && r.account == L"alice");

    r = Logon(Batch, Submit(L"PC\\ALICE", false));                    // normalized
    CHECK(r.status == kAccountRestrict && r.account == L"PC\\ALICE");

    r = Logon(Network, Submit(L"bob", false));                        // not enrolled
    CHECK(r.status == kInvalidLogonType && r.account == L"bob");
    CHECK(fake::events.back() == 202);

    r = Logon(Interactive, Submit(L"alice", false));                  // tile path: decline
    CHECK(r.status == kInvalidLogonType && r.account == L"alice");    // name still audited

    r = Logon(Network, Submit(L"x", false, KerbSmartCardLogon));      // not our layout
    CHECK(r.status == kInvalidLogonType && r.account == L"-");

    r = Logon(Network, {});                                           // no buffer
    CHECK(r.status == kInvalidLogonType && r.account == L"-");

    std::printf("-- authentication package: non-ASCII names (locale-invariant folding)\n");
    if (std::setlocale(LC_CTYPE, "C.UTF-8"))
    {
        r = Logon(Network, Submit(L"JÖRG", false));
        CHECK(r.status == kAccountRestrict);
        fake::failLcMap = true;                                        // ASCII-only fallback
        r = Logon(Network, Submit(L"JÖRG", false));
        CHECK(r.status == kInvalidLogonType);
        r = Logon(Network, Submit(L"ALICE", false));
        CHECK(r.status == kAccountRestrict);
        fake::failLcMap = false;
        std::setlocale(LC_CTYPE, "C");
    }
    else
    {
        std::printf("skip  C.UTF-8 locale not available\n");
    }

    std::printf("-- authentication package: hostile buffers\n");
    std::vector<BYTE> b = Submit(L"alice", false);
    reinterpret_cast<KERB_INTERACTIVE_LOGON*>(b.data())->UserName.Length += sizeof(WCHAR);
    r = Logon(Network, b);                                            // runs past the buffer
    CHECK(r.status == kInvalidLogonType && r.account == L"-");

    b = Submit(L"alice", false);
    reinterpret_cast<KERB_INTERACTIVE_LOGON*>(b.data())->UserName.Length = 3;
    r = Logon(Network, b);                                            // odd byte count
    CHECK(r.status == kInvalidLogonType && r.account == L"-");

    b = Submit(L"alice", false);
    reinterpret_cast<KERB_INTERACTIVE_LOGON*>(b.data())->UserName.Buffer =
        reinterpret_cast<PWSTR>(kClientBase - 64);
    r = Logon(Network, b);                                            // points before it
    CHECK(r.status == kInvalidLogonType && r.account == L"-");

    b = Submit(L"alice", false);
    b.resize(sizeof(KERB_INTERACTIVE_LOGON) - 1);
    r = Logon(Network, b);                                            // truncated header
    CHECK(r.status == kInvalidLogonType && r.account == L"-");

    r = Logon(Network, Submit(std::wstring(L"al\0ice", 6), false));  // stops at NUL
    CHECK(r.account == L"al");

    r = Logon(Network, Submit(std::wstring(300, L'n'), false));       // capped at UNLEN
    CHECK(r.account.size() == 256);

    std::printf("-- authentication package: fail closed\n");
    fake::openStatus = ERROR_ACCESS_DENIED;
    r = Logon(Network, Submit(L"bob", false));                        // unreadable index
    CHECK(r.status == kAccountRestrict && r.account == L"bob");
    CHECK(fake::DebugContains(L"could not be read"));
    fake::openStatus = ERROR_SUCCESS;

    fake::throwOnOpen = true;
    r = Logon(Network, Submit(L"bob", false));                        // fault: deny
    CHECK(r.status == kAccountRestrict && r.account == L"-");
    CHECK(fake::DebugContains(L"after an exception"));
    r = Logon(Interactive, Submit(L"bob", false));                    // no read, no fault
    CHECK(r.status == kInvalidLogonType);
    fake::throwOnOpen = false;

    std::printf("-- authentication package: AccountName edge cases\n");
    r = Logon(Network, Submit(L"alice", false), false);               // caller passed null
    CHECK(r.status == kAccountRestrict && !r.haveAccount);

    fake::allocBudget = 1;                                             // struct ok, buffer fails
    r = Logon(Network, Submit(L"alice", false));
    CHECK(r.status == kAccountRestrict && !r.haveAccount);
    fake::allocBudget = 0;
    r = Logon(Network, Submit(L"alice", false));
    CHECK(r.status == kAccountRestrict && !r.haveAccount);
    fake::allocBudget = -1;

    CHECK(fake::lsaAllocs == fake::lsaFrees);                         // nothing leaked
    CHECK(fake::opened == fake::closed);
}

// ---- the index reads -------------------------------------------------------

static void TestIndex()
{
    std::printf("-- index: NormalizeUserInto\n");
    fake::Reset();
    WCHAR out[8];
    CHECK(tac::NormalizeUserInto(L"PC\\Alice", 8, out, 8) && std::wcscmp(out, L"alice") == 0);
    CHECK(tac::NormalizeUserInto(L".\\bob", 5, out, 8) && std::wcscmp(out, L"bob") == 0);
    CHECK(!tac::NormalizeUserInto(L"", 0, out, 8));
    CHECK(!tac::NormalizeUserInto(L"PC\\", 3, out, 8));
    CHECK(!tac::NormalizeUserInto(L"abcdefgh", 8, out, 8));            // does not fit
    CHECK(tac::NormalizeUserInto(L"abcdefg", 7, out, 8) && std::wcscmp(out, L"abcdefg") == 0);
    CHECK(!tac::NormalizeUserInto(nullptr, 3, out, 8));

    std::printf("-- index: three outcomes\n");
    CHECK(tac::EnrollmentByRid(1001) == tac::Enrollment::No);         // no key at all
    fake::keys[kRids] = { L"1001" };
    CHECK(tac::EnrollmentByRid(1001) == tac::Enrollment::Yes);
    CHECK(tac::EnrollmentByRid(1002) == tac::Enrollment::No);
    fake::queryStatus = ERROR_ACCESS_DENIED;
    CHECK(tac::EnrollmentByRid(1001) == tac::Enrollment::Unknown);
    CHECK(!tac::IsEnrolledByRid(1001));                                // non-vetoing view
    fake::queryStatus = ERROR_SUCCESS;
    CHECK(tac::EnrollmentByName(L"", 0) == tac::Enrollment::Unknown); // unusable name
    CHECK(fake::opened == fake::closed);
}

int main()
{
    TestFilter();
    TestAuthPackage();
    TestIndex();

    std::printf("\n%s (%d failed)\n", g_failed ? "SOME CHECKS FAILED" : "ALL CHECKS PASS", g_failed);
    return g_failed ? 1 : 0;
}
