// game/GameLuaContextLua51.cpp — Lua 5.1 context instance
#include "game/GameLuaContextLua51.hpp"
#include "game/GameLuaInternal.hpp"

using ds::core_vm::detail::DefaultLua51LibraryName;

static GameLua51Context gameLua51Ctx{
        DefaultLua51LibraryName(),
        GameLuaType::_51};

namespace ds::core_vm::detail {
GameLuaContextImpl *ctx_lua51() { return &gameLua51Ctx; }
} // namespace ds::core_vm::detail
