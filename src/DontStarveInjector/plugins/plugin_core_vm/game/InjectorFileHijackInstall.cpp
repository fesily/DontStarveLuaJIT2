// game/InjectorFileHijackInstall.cpp — installs the file hijack on this VM's C-function hook
// service (GameLuaContextImpl::cfuncHooks): `require` and `kleiloadlua` keep their stock Lua
// objects, and the hook table/registry stay in C++.
//
// The service lives in the VM context, so a VM switch reverts these hooks in ResetApis and the
// next state that loads main.lua installs them again; the state's close only drops its
// installations.
#include "game/GameLuaContextImpl.hpp"
#include "game/InjectorFileHijack.hpp"

void GameLuaContextImpl::install_injector_file_hooks(lua_State *L) {
    // Both hooks carry this context; the policy resolves the root and reads
    // GameLuaInjector.relocations / calls GameLuaInjector.run_inject from it, never GLOBAL.
    cfuncHooks.hook_global(api, L, "require", &ds::core_vm::detail::file_hijack_policy, nullptr);
    cfuncHooks.hook_global(api, L, "kleiloadlua", &ds::core_vm::detail::file_hijack_policy, nullptr);
}
