// L0 lua_event bus: plugins register listeners; notifyer does not hardcode DLL names.
#include "plugins/plugin_core_vm/LuaEvent.hpp"

#include <vector>
#include <doctest/doctest.h>

// listeners use free-function C API from LuaEvent.hpp

namespace {

int g_calls = 0;
LUA_EVENT g_last = LUA_EVENT::new_state;
lua_State *g_last_L = nullptr;

void listener_a(LUA_EVENT ev, lua_State *L) {
    ++g_calls;
    g_last = ev;
    g_last_L = L;
}

int g_calls_b = 0;
void listener_b(LUA_EVENT, lua_State *) { ++g_calls_b; }

} // namespace

// Lifecycle order matters: the bus has no unregister/reset API, so registration,
// duplicate rejection and notification all depend on the steps before them.
TEST_CASE("test_lua_event_bus/all") {
    // Clear by re-registering only after; first notify with empty bus is fine.
    lua_event_notifyer(LUA_EVENT::new_state, nullptr);

    g_calls = 0;
    g_last_L = reinterpret_cast<lua_State *>(0x1);
    REQUIRE(ds_register_lua_event_listener(&listener_a));
    auto *L = reinterpret_cast<lua_State *>(0xABCDu);
    lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
    REQUIRE_EQ(g_calls, 1);
    REQUIRE_EQ(g_last, LUA_EVENT::call_lua_gc);
    REQUIRE_EQ(g_last_L, L);

    g_calls = 0;
    REQUIRE_FALSE(ds_register_lua_event_listener(&listener_a)); // already registered
    lua_event_notifyer(LUA_EVENT::close_state, nullptr);
    REQUIRE_EQ(g_calls, 1);

    g_calls = 0;
    g_calls_b = 0;
    REQUIRE(ds_register_lua_event_listener(&listener_b));
    lua_event_notifyer(LUA_EVENT::new_state, nullptr);
    REQUIRE_EQ(g_calls, 1);
    REQUIRE_EQ(g_calls_b, 1);
}
