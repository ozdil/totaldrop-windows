// SPDX-FileCopyrightText: 2026 The TotalDrop Contributors
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Minimal, zero-exception C++20 COM `IExplorerCommand` shim compiled separately
// for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` as
// `totaldrop_explorer_ext.dll`.
//
// All path validation, extended `\\?\` normalization, 35-language verb lookup,
// and length-prefixed Named Pipe framing delegate to TotalDrop's Rust bridge
// (`totaldrop_windows_bridge`).

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shlwapi.h>
#include <shobjidl_core.h>
#include <atomic>
#include <new>
#include <string>
#include <vector>

// {8F6E3D72-4B9A-4E1C-9D3A-7C2F5A81E4B0}
static constexpr CLSID CLSID_TotalDropSendExplorerCommand = {
    0x8f6e3d72, 0x4b9a, 0x4e1c, {0x9d, 0x3a, 0x7c, 0x2f, 0x5a, 0x81, 0xe4, 0xb0}};

static std::atomic<long> g_moduleRefCount{0};
static HMODULE g_moduleInstance = nullptr;

extern "C" {
// Provided by totaldrop_windows_bridge C ABI:
// - Resolves localized "Send with TotalDrop" across 35 languages into CoTaskMem UTF-16.
HRESULT totaldrop_explorer_get_verb_utf16(
    const wchar_t* preferred_ui_languages_msz,
    LPWSTR* out_cotaskmem_title) noexcept;

// - Validates IShellItemArray UTF-16 paths (`\\?\` extended-length safe) and
//   dispatches via session Named Pipe IPC or CreateProcessW (never cmd.exe).
HRESULT totaldrop_explorer_invoke_selection(
    const wchar_t* const* raw_paths,
    size_t path_count,
    DWORD session_id) noexcept;
}

final class TotalDropExplorerCommand final : public IExplorerCommand {
public:
    TotalDropExplorerCommand() noexcept {
        g_moduleRefCount.fetch_add(1, std::memory_order_relaxed);
    }

    ~TotalDropExplorerCommand() noexcept {
        g_moduleRefCount.fetch_sub(1, std::memory_order_relaxed);
    }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) noexcept override {
        if (ppv == nullptr) {
            return E_POINTER;
        }
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IExplorerCommand)) {
            *ppv = static_cast<IExplorerCommand*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() noexcept override {
        return _refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    IFACEMETHODIMP_(ULONG) Release() noexcept override {
        const ULONG remaining = _refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    // IExplorerCommand
    IFACEMETHODIMP GetTitle(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszName) noexcept override {
        if (ppszName == nullptr) {
            return E_POINTER;
        }
        *ppszName = nullptr;

        ULONG numLangs = 0;
        ULONG cchBuf = 0;
        if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &numLangs, nullptr, &cchBuf) && cchBuf > 0) {
            std::vector<wchar_t> buffer(cchBuf, L'\0');
            if (GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &numLangs, buffer.data(), &cchBuf)) {
                return totaldrop_explorer_get_verb_utf16(buffer.data(), ppszName);
            }
        }
        return SHStrDupW(L"Send with TotalDrop", ppszName);
    }

    IFACEMETHODIMP GetIcon(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszIcon) noexcept override {
        if (ppszIcon == nullptr) {
            return E_POINTER;
        }
        wchar_t modulePath[MAX_PATH]{};
        if (GetModuleFileNameW(g_moduleInstance, modulePath, MAX_PATH) == 0) {
            *ppszIcon = nullptr;
            return E_FAIL;
        }
        std::wstring iconSpec(modulePath);
        iconSpec.append(L",-101");
        return SHStrDupW(iconSpec.c_str(), ppszIcon);
    }

    IFACEMETHODIMP GetToolTip(IShellItemArray* /*psiItemArray*/, LPWSTR* ppszInfotip) noexcept override {
        if (ppszInfotip == nullptr) {
            return E_POINTER;
        }
        *ppszInfotip = nullptr;
        return E_NOTIMPL;
    }

    IFACEMETHODIMP GetCanonicalName(GUID* pguidCommandName) noexcept override {
        if (pguidCommandName == nullptr) {
            return E_POINTER;
        }
        *pguidCommandName = CLSID_TotalDropSendExplorerCommand;
        return S_OK;
    }

    IFACEMETHODIMP GetState(
        IShellItemArray* psiItemArray,
        BOOL /*fOkToBeSlow*/,
        EXPCMDSTATE* pCmdState) noexcept override {
        if (pCmdState == nullptr) {
            return E_POINTER;
        }
        DWORD count = 0;
        if (psiItemArray == nullptr || FAILED(psiItemArray->GetCount(&count)) || count == 0) {
            *pCmdState = ECS_HIDDEN;
            return S_OK;
        }
        *pCmdState = ECS_ENABLED;
        return S_OK;
    }

    IFACEMETHODIMP Invoke(IShellItemArray* psiItemArray, IBindCtx* /*pbc*/) noexcept override {
        if (psiItemArray == nullptr) {
            return E_INVALIDARG;
        }
        DWORD count = 0;
        HRESULT hr = psiItemArray->GetCount(&count);
        if (FAILED(hr) || count == 0) {
            return S_OK;
        }
        if (count > 10000) {
            return HRESULT_FROM_WIN32(ERROR_BUFFER_OVERFLOW);
        }

        std::vector<std::wstring> ownedPaths;
        std::vector<const wchar_t*> rawPointers;
        ownedPaths.reserve(count);
        rawPointers.reserve(count);

        for (DWORD idx = 0; idx < count; ++idx) {
            IShellItem* item = nullptr;
            if (SUCCEEDED(psiItemArray->GetItemAt(idx, &item)) && item != nullptr) {
                LPWSTR fileSysPath = nullptr;
                if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &fileSysPath)) && fileSysPath != nullptr) {
                    ownedPaths.emplace_back(fileSysPath);
                    CoTaskMemFree(fileSysPath);
                }
                item->Release();
            }
        }
        if (ownedPaths.empty()) {
            return S_OK;
        }
        for (const auto& s : ownedPaths) {
            rawPointers.push_back(s.c_str());
        }

        DWORD sessionId = 0;
        ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
        return totaldrop_explorer_invoke_selection(rawPointers.data(), rawPointers.size(), sessionId);
    }

    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* pFlags) noexcept override {
        if (pFlags == nullptr) {
            return E_POINTER;
        }
        *pFlags = ECF_DEFAULT;
        return S_OK;
    }

    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** ppEnum) noexcept override {
        if (ppEnum != nullptr) {
            *ppEnum = nullptr;
        }
        return E_NOTIMPL;
    }

private:
    std::atomic<ULONG> _refCount{1};
};

final class TotalDropClassFactory final : public IClassFactory {
public:
    TotalDropClassFactory() noexcept {
        g_moduleRefCount.fetch_add(1, std::memory_order_relaxed);
    }

    ~TotalDropClassFactory() noexcept {
        g_moduleRefCount.fetch_sub(1, std::memory_order_relaxed);
    }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) noexcept override {
        if (ppv == nullptr) {
            return E_POINTER;
        }
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IClassFactory)) {
            *ppv = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    IFACEMETHODIMP_(ULONG) AddRef() noexcept override {
        return _refCount.fetch_add(1, std::memory_order_relaxed) + 1;
    }

    IFACEMETHODIMP_(ULONG) Release() noexcept override {
        const ULONG remaining = _refCount.fetch_sub(1, std::memory_order_acq_rel) - 1;
        if (remaining == 0) {
            delete this;
        }
        return remaining;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) noexcept override {
        if (ppv == nullptr) {
            return E_POINTER;
        }
        *ppv = nullptr;
        if (pUnkOuter != nullptr) {
            return CLASS_E_NOAGGREGATION;
        }
        auto* cmd = new (std::nothrow) TotalDropExplorerCommand();
        if (cmd == nullptr) {
            return E_OUTOFMEMORY;
        }
        const HRESULT hr = cmd->QueryInterface(riid, ppv);
        cmd->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL fLock) noexcept override {
        if (fLock) {
            g_moduleRefCount.fetch_add(1, std::memory_order_relaxed);
        } else {
            g_moduleRefCount.fetch_sub(1, std::memory_order_relaxed);
        }
        return S_OK;
    }

private:
    std::atomic<ULONG> _refCount{1};
};

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID /*lpvReserved*/) noexcept {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_moduleInstance = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
    }
    return TRUE;
}

extern "C" STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID* ppv) noexcept {
    if (ppv == nullptr) {
        return E_POINTER;
    }
    *ppv = nullptr;
    if (rclsid != CLSID_TotalDropSendExplorerCommand) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    auto* factory = new (std::nothrow) TotalDropClassFactory();
    if (factory == nullptr) {
        return E_OUTOFMEMORY;
    }
    const HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}

extern "C" STDAPI DllCanUnloadNow() noexcept {
    return g_moduleRefCount.load(std::memory_order_acquire) == 0 ? S_OK : S_FALSE;
}
