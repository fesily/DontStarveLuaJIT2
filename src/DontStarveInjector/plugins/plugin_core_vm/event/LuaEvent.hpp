#pragma once
// Owned by plugin_core_vm — LUA_EVENT codes + listener bus.
// Notify is internal to core.vm (GameLua). Peers register via host service
// "ds_register_lua_event_listener" (module_init of core.vm).
// Intentionally does NOT include GameLua.hpp / LuaJIT headers.

struct lua_State; // opaque; only passed through to plugins

enum class LUA_EVENT {
    new_state,
    close_state,
    call_lua_gc,
};

// Fan-out to registered listeners (defined in LuaEventBus.cpp / plugin_core_vm).
void lua_event_notifyer(LUA_EVENT ev, lua_State *L);

// C ABI for host service table (stable function pointer).
extern "C" bool ds_register_lua_event_listener(void (*fn)(LUA_EVENT, lua_State *));
