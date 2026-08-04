#pragma once
// Shared LUA_EVENT codes + process-wide listener bus.
// Intentionally does NOT include GameLua.hpp / LuaJIT headers.
// Plugins register listeners; L0 notifyer fans out — no hardcoded DLL names.

struct lua_State; // opaque; only passed through to plugins

enum class LUA_EVENT {
    new_state,
    close_state,
    call_lua_gc,
};

#ifndef DS_INJECTOR_CXX_API
#  include "config.hpp"
#endif

// Fan-out to all registered listeners (defined in LuaEventBus.cpp / Injector).
DS_INJECTOR_CXX_API void lua_event_notifyer(LUA_EVENT ev, lua_State *L);

// Register a listener. Returns false if fn is null or already registered.
// C ABI so plugins can register without C++ name mangling issues.
extern "C" {
#ifndef DS_PLUGIN_HOST_STATIC
// When building Injector DLL, export; when plugin consumer, import.
#  if defined(_WIN32)
#    if defined(DONTSTARVEINJECTOR_BUILD)
#      define DS_LUA_EVENT_API __declspec(dllexport)
#    else
#      define DS_LUA_EVENT_API __declspec(dllimport)
#    endif
#  else
#    if defined(DONTSTARVEINJECTOR_BUILD)
#      define DS_LUA_EVENT_API __attribute__((visibility("default")))
#    else
#      define DS_LUA_EVENT_API
#    endif
#  endif
#else
#  define DS_LUA_EVENT_API
#endif
DS_LUA_EVENT_API bool ds_register_lua_event_listener(void (*fn)(LUA_EVENT, lua_State *));
}
