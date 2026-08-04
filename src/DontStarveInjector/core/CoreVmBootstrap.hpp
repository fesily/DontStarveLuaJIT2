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

// Ensure module (optional), call export when present.
// If export is null → log skip, return false (NO in-process legacy fallback).
// If export returns false → log soft skip, return false.
// Hard failures inside the plugin call showError (exit) themselves.
bool TryRunSignatureAndReplace(const BootstrapArgs &args);

} // namespace ds::core_vm
