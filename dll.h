#pragma once
#include <windows.h>

void DllAddRef();
void DllRelease();

HRESULT CTacProvider_CreateInstance(REFIID riid, void** ppv);
HRESULT CTacFilter_CreateInstance(REFIID riid, void** ppv);
