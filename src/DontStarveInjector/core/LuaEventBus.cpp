#include "config/InjectorHostConfig.hpp"
#include "LuaEvent.hpp"

#include <mutex>
#include <vector>

namespace {

using Listener = void (*)(LUA_EVENT, lua_State *);

std::mutex g_mu;
std::vector<Listener> g_listeners;

} // namespace

extern "C" bool ds_register_lua_event_listener(void (*fn)(LUA_EVENT, lua_State *)) {
    if (!fn) {
        return false;
    }
    std::lock_guard lock(g_mu);
    for (auto *existing : g_listeners) {
        if (existing == fn) {
            return false;
        }
    }
    g_listeners.push_back(fn);
    return true;
}

DS_INJECTOR_CXX_API void lua_event_notifyer(LUA_EVENT ev, lua_State *L) {
    // Snapshot under lock so listeners may re-enter register without deadlock.
    std::vector<Listener> snap;
    {
        std::lock_guard lock(g_mu);
        snap = g_listeners;
    }
    for (auto *fn : snap) {
        if (fn) {
            fn(ev, L);
        }
    }
}
