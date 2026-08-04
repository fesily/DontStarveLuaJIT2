#pragma once

#include <cstdint>

namespace ds::core_vm {

struct BootstrapArgs {
    bool is_client = true;
    uintptr_t lua_module_base = 0;
    const char *main_path = nullptr;
};

// Loads plugins/plugin_core_vm.{dll,so} if not already mapped.
// Returns false if module missing or load fails — never aborts process.
bool EnsureCoreVmModuleLoaded();

// Returns function pointer or nullptr when export is absent.
using RunSigReplaceFn = bool (*)(const BootstrapArgs *args);
RunSigReplaceFn GetRunSignatureAndReplaceFn();

// Full signature + ReplaceLuaModule path still owned by Injector until Task 3.
// Returns false only on hard failures (showError already called where appropriate).
bool LegacySignatureAndReplaceInInjector(const BootstrapArgs &args);

// Ensure module (optional), call export when present; false from stub falls back
// to LegacySignatureAndReplaceInInjector while implementation remains in Injector.
// Returns false only when the effective path hard-fails.
bool TryRunSignatureAndReplace(const BootstrapArgs &args);

} // namespace ds::core_vm
