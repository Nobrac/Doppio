#include <windows.h>
#include <new>

#include <initguid.h>
#include "guid.h"
#include "dll.h"

// Number of live objects. LogonUI calls DllCanUnloadNow from time to time and
// must not unload the DLL while a provider, credential or filter still exists.
static LONG g_cRef = 0;

void DllAddRef()  { InterlockedIncrement(&g_cRef); }
void DllRelease() { InterlockedDecrement(&g_cRef); }

class CClassFactory : public IClassFactory
{
public:
    explicit CClassFactory(REFCLSID rclsid) : _cRef(1), _clsid(rclsid) { DllAddRef(); }

    IFACEMETHODIMP_(ULONG) AddRef() { return InterlockedIncrement(&_cRef); }

    IFACEMETHODIMP_(ULONG) Release()
    {
        LONG cRef = InterlockedDecrement(&_cRef);
        if (cRef == 0)
            delete this;
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv)
    {
        if (!ppv)
            return E_POINTER;
        if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory))
        {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv)
    {
        if (pUnkOuter)
            return CLASS_E_NOAGGREGATION;
        if (IsEqualCLSID(_clsid, CLSID_CTacProvider))
            return CTacProvider_CreateInstance(riid, ppv);
        if (IsEqualCLSID(_clsid, CLSID_CTacFilter))
            return CTacFilter_CreateInstance(riid, ppv);
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    IFACEMETHODIMP LockServer(BOOL fLock)
    {
        if (fLock)
            DllAddRef();
        else
            DllRelease();
        return S_OK;
    }

private:
    ~CClassFactory() { DllRelease(); }

    LONG  _cRef;
    CLSID _clsid;
};

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = nullptr;
    if (!IsEqualCLSID(rclsid, CLSID_CTacProvider) && !IsEqualCLSID(rclsid, CLSID_CTacFilter))
        return CLASS_E_CLASSNOTAVAILABLE;

    CClassFactory* pcf = new (std::nothrow) CClassFactory(rclsid);
    if (!pcf)
        return E_OUTOFMEMORY;

    HRESULT hr = pcf->QueryInterface(riid, ppv);
    pcf->Release();
    return hr;
}

STDAPI DllCanUnloadNow()
{
    return InterlockedCompareExchange(&g_cRef, 0, 0) == 0 ? S_OK : S_FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID)
{
    if (dwReason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(hModule);
    return TRUE;
}
