#pragma once

#include <cstdint>

namespace ds::core_vm {

struct BootstrapArgs {
    bool is_client = true;
    uintptr_t lua_module_base = 0;
    const char *main_path = nullptr;
};

// Loads plugins/plugin_core_vm.{dll,so} if not already mapped.
// Required for normal inject. DS_LUAJIT_FORCE_NO_CORE_VM=1 is CI-only soft skip.
bool EnsureCoreVmModuleLoaded();

// Returns function pointer or nullptr when export is absent.
using RunSigReplaceFn = bool (*)(const BootstrapArgs *args);
RunSigReplaceFn GetRunSignatureAndReplaceFn();

// Force-load core.vm and run signature/replace.
// Module missing / export missing → hard fail (showError/exit) unless CI env
// DS_LUAJIT_FORCE_NO_CORE_VM=1. Soft skip only when VM path is intentionally
// disabled (DisableJITWhenServer / DS_LUAJIT_FORCE_DISABLE_VM) or soft miss
// (no luamodule base). Hard failures inside the plugin also showError.
bool ForceRunSignatureAndReplace(const BootstrapArgs &args);

// Backward-compatible name used by older call sites; same as ForceRun...
bool TryRunSignatureAndReplace(const BootstrapArgs &args);

} // namespace ds::core_vm
