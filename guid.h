#pragma once
#include <guiddef.h>

// Generate your own GUIDs before using this anywhere and keep them in sync
// with the .reg files. dll.cpp includes initguid.h before this header, so the
// GUIDs are defined there and only declared everywhere else.

// {B1E7C9A0-2F4D-4C6B-9A11-0000C0FFEE01}
DEFINE_GUID(CLSID_CTacProvider,
    0xb1e7c9a0, 0x2f4d, 0x4c6b, 0x9a, 0x11, 0x00, 0x00, 0xc0, 0xff, 0xee, 0x01);

// {B1E7C9A0-2F4D-4C6B-9A11-0000C0FFEE02}
DEFINE_GUID(CLSID_CTacFilter,
    0xb1e7c9a0, 0x2f4d, 0x4c6b, 0x9a, 0x11, 0x00, 0x00, 0xc0, 0xff, 0xee, 0x02);
