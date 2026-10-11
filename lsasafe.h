#pragma once
//
// Helpers for code that runs INSIDE lsass.exe (the authentication package in
// ap.cpp and the sub-authentication filter in subauth.cpp). The three rules,
// learned the hard way in Part 3 (Ristretto):
//
//   * No heap and no CRT of our own on the decision path. std::wstring can
//     throw std::bad_alloc; swprintf_s calls the invalid-parameter handler on
//     overflow, and the default handler ends the process - here lsass, which
//     is a bugcheck. Build log lines with Buf (it cuts instead) and format
//     numbers without the CRT. (Windows APIs we call - the registry,
//     OutputDebugString, the event log - allocate inside Windows; that is
//     theirs to get right, and none of them throws into our code.)
//   * SEH, not C++ try/catch. With /EHsc a catch (...) does not catch an
//     access violation, and a bad pointer from the caller is the failure that
//     actually matters here. The decision runs behind one __except whose
//     filter is LsaDecisionExceptionFilter.
//
// Both files shared private copies of this before; keeping one copy means a
// fix lands in both at once.

#include <windows.h>

namespace tac
{
    // Bounded, CRT-free wide-string builder. Never writes past `cap`, always
    // null-terminates, and simply stops appending when full (no overflow, no
    // invalid-parameter handler, nothing that could end lsass).
    class Buf
    {
    public:
        Buf(WCHAR* p, SIZE_T cap) : p_(p), cap_(cap), n_(0)
        {
            if (cap_) p_[0] = L'\0';
        }

        void Str(const WCHAR* s)
        {
            if (!s) return;
            while (*s && n_ + 1 < cap_) p_[n_++] = *s++;
            if (cap_) p_[n_] = L'\0';
        }

        void U64(ULONGLONG v)
        {
            WCHAR t[21];
            int i = 0;
            do { t[i++] = (WCHAR)(L'0' + (ULONG)(v % 10)); v /= 10; } while (v && i < 20);
            while (i > 0 && n_ + 1 < cap_) p_[n_++] = t[--i];
            if (cap_) p_[n_] = L'\0';
        }

    private:
        WCHAR* p_;
        SIZE_T cap_;
        SIZE_T n_;
    };

    // Which exceptions the __except around a decision swallows. A stack
    // overflow is not ours to survive: the guard page is gone by the time we
    // run. Everything else here means a bad pointer from the caller, and on
    // that one a dead lsass is the worse outcome, so it is caught and the
    // caller fails closed.
    inline LONG LsaDecisionExceptionFilter(DWORD code)
    {
        switch (code)
        {
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_NONCONTINUABLE_EXCEPTION:
            return EXCEPTION_CONTINUE_SEARCH;
        default:
            return EXCEPTION_EXECUTE_HANDLER;
        }
    }
}
