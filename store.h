#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace tac
{
    // "PC\Alice", ".\alice" and "alice" all become "alice". Case folding is
    // locale-invariant, so non-ASCII names fold the same way everywhere.
    std::wstring NormalizeUser(const std::wstring& user);

    // The same, for code inside lsass: `user` is counted (cch characters, it
    // may also end early at a NUL), the result goes into a caller buffer, and
    // nothing allocates. Returns false for an empty name or one that does not
    // fit. Lives in store_index.cpp.
    bool NormalizeUserInto(const WCHAR* user, SIZE_T cch, WCHAR* out, SIZE_T outCap);

    // Looks up COMPUTERNAME\name and returns the SID string ("S-1-5-21-...")
    // if it is a local user account. Everything else returns false.
    bool ResolveLocalUserSid(const std::wstring& user, std::wstring& sid);

    // The last sub-authority of a SID string, the RID ("...-1001" -> 1001).
    // Returns false for anything that is not a well-formed SID string.
    bool RidFromSidString(const std::wstring& sid, DWORD& rid);

    // Is this a syntactically valid SID string ("S-1-...")? Lets enroll accept
    // a SID where a name no longer resolves.
    bool IsSidString(const std::wstring& sid);

    // The secret is stored per SID, not per name. A renamed or re-created
    // account is a different account. StoreSecret also mirrors two enrollment
    // indexes for code that runs inside lsass: one keyed by RID (see
    // EnrollmentByRid) and one keyed by name (see EnrollmentByName).
    bool StoreSecret(const std::wstring& sid, const std::string& base32Secret);
    bool LoadSecretKey(const std::wstring& sid, std::vector<BYTE>& key);

    // Hot-path enrollment checks for code that runs INSIDE lsass. Each is a
    // single registry read: no DPAPI decrypt and no account-name or SID lookup,
    // so nothing calls back into LSA and the logon path cannot deadlock.
    // Neither allocates: a caller in lsass must not risk std::bad_alloc.
    //
    // Three outcomes, because a caller that VETOES must not read a failed read
    // as "not enrolled" - that is the one wrong answer that lets an enrolled
    // account through. A missing index key is No (nothing indexed on this
    // machine at all); any other read error is Unknown.
    enum class Enrollment { No, Yes, Unknown };

    // EnrollmentByRid is the one to use whenever the caller has the account's
    // RID from the SAM (the MSV1_0 sub-authentication filter gets it in
    // USER_ALL_INFORMATION). A RID survives a rename and the SAM never hands
    // out a RID twice, so this index can neither miss a renamed account nor
    // match a different, re-created one.
    Enrollment EnrollmentByRid(DWORD rid);

    // IsEnrolledByRid is EnrollmentByRid(rid) == Yes, so it reads every failure
    // as "not enrolled". Only for callers that do not veto.
    bool IsEnrolledByRid(DWORD rid);

    // EnrollmentByName is only for callers that have nothing but the name a
    // client typed (the authentication package). `name` is counted, not
    // null-terminated, and is normalized into a fixed buffer here.
    //
    // It is weaker than the RID check and fails OPEN in one case: after an
    // enrolled account is renamed, the index still holds the old name, so the
    // new name reads as "not enrolled" until `enroll /reindex` runs. A
    // re-created account with an old name reads as enrolled (more
    // restrictive). Prefer EnrollmentByRid wherever the RID is available.
    Enrollment EnrollmentByName(const WCHAR* name, SIZE_T cch);

    // Removes an enrollment completely: the DPAPI secret, the state and the RID
    // index entry under the SID, and the name-keyed index entry. Both halves are
    // removed independently on purpose. The name entry has to go even when the
    // Windows account was already deleted and the SID can no longer be resolved -
    // otherwise that name stays "enrolled" forever. (A RID entry of a deleted
    // account is harmless: the SAM never reuses the RID.)
    // An empty user or sid simply skips that half. A value that is not there
    // counts as removed.
    bool RemoveEnrollment(const std::wstring& user, const std::wstring& sid);

    // Is at least one account enrolled? Counts only stored secrets: REG_BINARY
    // values whose name is a SID string. A stray value of another type or name
    // does not count, because the credential provider's filter hides every
    // other sign-in option as soon as this says yes - and it must not do that
    // when nothing can actually authenticate.
    // Returns false if the store exists but cannot be read; a store that does
    // not exist yet is "readable, nothing enrolled".
    bool QueryAnyEnrollment(bool& any);

    // One enrolled account, for `enroll /list`.
    struct EnrollmentEntry
    {
        std::wstring sid;
        std::wstring name;      // empty when the SID no longer resolves
        DWORD        rid;
        bool         ridIndexed;
        bool         nameIndexed;
    };

    // Every stored secret with its index state. Returns false if the store
    // cannot be read; an empty store is "readable, nothing enrolled".
    bool ListEnrollments(std::vector<EnrollmentEntry>& out);

    // Removes everything this project keeps in the registry: secrets, state
    // and both indexes. For a full uninstall. A tree that is not there counts
    // as removed.
    bool PurgeAllEnrollments();

    // Re-applies the "SYSTEM and Administrators only" ACL to the store keys
    // that already exist. New keys get it when they are created; this repairs
    // keys left over from an older version with a weaker ACL. Called by
    // enroll.exe, never from the logon path - it needs WRITE_DAC and writes to
    // the hive, and neither belongs in a logon.
    bool EnsureStoreAcls();

    // Rebuilds the RID and name indexes from the stored secrets. For accounts
    // that were enrolled before the RID index existed, and after a rename.
    // Stale name entries of renamed accounts are left alone (they only make the
    // name check stricter). Returns the number of enrollments indexed, -1 if
    // the enrollments cannot be read or a RID entry cannot be written.
    int ReindexEnrollments();

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
    // A read-modify-write of the state must hold a StateLock (statelock.h).
    bool LoadState(const std::wstring& sid, UserState& state);
    bool SaveState(const std::wstring& sid, const UserState& state);
    bool DeleteState(const std::wstring& sid);
}
