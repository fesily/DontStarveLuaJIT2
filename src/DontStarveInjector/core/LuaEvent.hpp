#pragma once
// Shared LUA_EVENT codes for Injector ↔ core.vm ↔ debug.profiler.
// Intentionally does NOT include GameLua.hpp / LuaJIT headers.

struct lua_State; // opaque; only passed through to plugins

enum class LUA_EVENT {
    new_state,
    close_state,
    call_lua_gc,
};

// Defined in Injector (forwards to plugin_debug_profiler when staged).
#ifndef DS_INJECTOR_CXX_API
#  include "config.hpp"
#endif
DS_INJECTOR_CXX_API void lua_event_notifyer(LUA_EVENT ev, lua_State *L);
