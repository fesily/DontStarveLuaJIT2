#pragma once
// core.vm fixed signatures: the Lua module anchor, the debug-getsize registration
// contract, the engine execution-error storage helper, the dev-build-type flag and
// the macOS version-string probe.
//
// This TU is linked by plugin_core_vm (runtime consumer), the offline tool and the
// Linux verifier. It owns only definitions, read-only decode helpers and the
// optional repair hook — never hooks, never game state.

#include "ProviderDesc.hpp"

#include <cstdint>

namespace ds::core_vm::detail {

// Decode the engine's execution-error storage from the window matched by
// core.vm.execution_error: the `cmp [flag], 0` slot, and the block as the `lea`
// target of the register that the `mov [flag], …` store publishes (not simply
// the window's first `lea`). Zero fields mean "not recognized" (fail closed).
struct ExecutionErrorStorage {
    uintptr_t flag = 0;
    uintptr_t buffer = 0;
    explicit operator bool() const { return flag != 0 && buffer != 0; }
};
ExecutionErrorStorage decode_execution_error_storage(uintptr_t helper);

} // namespace ds::core_vm::detail

namespace ds::core_vm {

// Entry table + read-only verifiers. The owning plugin's module_init publishes it
// through PluginHost::register_signature_provider(); the offline tool links the
// same TU and drives the table through the stateless runner.
const ds::sig::ProviderDesc &signature_provider();

// Base address of the Lua module this process resolved (core.vm.lua_module).
// Set once, before any consumer installs base-API hooks; the Lua signature DB
// stores offsets relative to it, so consumers must not re-derive it themselves.
uintptr_t lua_module_base();
void set_lua_module_base(uintptr_t base);

// macOS only: the version string the engine embeds is the only version source
// there (no version.txt on those builds). Returns -1 when the probe fails.
intptr_t read_game_version_from_memory();

} // namespace ds::core_vm
