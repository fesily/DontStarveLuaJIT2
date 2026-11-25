#pragma once
// Injector file hijack (relocation + one-shot module afterload) — the policy the generic
// C-function hook (game/CfunctionHook.hpp) runs on top of `require` and `kleiloadlua`.
#include "game/CfunctionHook.hpp"
#include "game/GameLuaContext.hpp"

// Global table the Lua framework installs (GameLuaInjectFramework.lua).
#define GameLuaInjectorName "GameLuaInjector"

namespace ds::core_vm::detail {

int file_hijack_policy(LuaApis &api, lua_State *L, lua_CFunction original, void *userdata);

} // namespace ds::core_vm::detail
