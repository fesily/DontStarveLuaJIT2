// L0 lua_event bus: plugins register listeners; notifyer does not hardcode DLL names.
#include "core/LuaEvent.hpp"

#include <cassert>
#include <cstdio>
#include <vector>

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

static void test_no_listener_is_noop() {
    // Clear by re-registering only after; first notify with empty bus is fine.
    lua_event_notifyer(LUA_EVENT::new_state, nullptr);
    printf("PASS: no_listener_is_noop\n");
}

static void test_register_and_notify() {
    g_calls = 0;
    g_last_L = reinterpret_cast<lua_State *>(0x1);
    assert(ds_register_lua_event_listener(&listener_a));
    auto *L = reinterpret_cast<lua_State *>(0xABCDu);
    lua_event_notifyer(LUA_EVENT::call_lua_gc, L);
    assert(g_calls == 1);
    assert(g_last == LUA_EVENT::call_lua_gc);
    assert(g_last_L == L);
    printf("PASS: register_and_notify\n");
}

static void test_duplicate_register_ignored() {
    g_calls = 0;
    assert(!ds_register_lua_event_listener(&listener_a)); // already registered
    lua_event_notifyer(LUA_EVENT::close_state, nullptr);
    assert(g_calls == 1);
    printf("PASS: duplicate_register_ignored\n");
}

static void test_multiple_listeners() {
    g_calls = 0;
    g_calls_b = 0;
    assert(ds_register_lua_event_listener(&listener_b));
    lua_event_notifyer(LUA_EVENT::new_state, nullptr);
    assert(g_calls == 1);
    assert(g_calls_b == 1);
    printf("PASS: multiple_listeners\n");
}

int main() {
    test_no_listener_is_noop();
    test_register_and_notify();
    test_duplicate_register_ignored();
    test_multiple_listeners();
    printf("ALL PASS: lua_event_bus\n");
    return 0;
}
