// game/DumpAttribution.cpp — string.dump attribution through the C-function hook.
//
// Installed once per state (luaL_openlibs_hooker) when the loaded VM image exposes the PUC 5.1
// dump bridge. The hook rewrites the closure's implementation pointer, so the Lua-visible object
// never changes and an alias saved before the install still reaches this policy (the field is
// read at call time; the JIT does not cache it). The VM's own string_dump no longer calls Lua.
#include "game/DumpAttribution.hpp"

#include "game/PrivateLuaRegistry.hpp"

namespace ds::core_vm::detail {

namespace {

// Private-root field the blacklist manager publishes (Mod/scripts/luajit_mod_blacklist.lua).
constexpr const char *kPolicyKey = "LJ_DS_PUC51_DUMP_POLICY";

bool g_puc_dump_available = false;

} // namespace

void set_puc_dump_available(bool available) {
    g_puc_dump_available = available;
}

bool puc_dump_available() {
    return g_puc_dump_available;
}

int dump_attribution_policy(LuaApis &api, lua_State *L, lua_CFunction original, void *userdata) {
    (void) userdata; // the manager's state lives in the private root, not in this slot
    const int nargs = api._lua_gettop(L);
    // The old VM callback ran after lua_lib_checkLproto, i.e. only for a call whose first
    // argument is a function. An invalid call still gets the original's own error, unrecorded.
    if (nargs < 1 || !api._lua_isfunction(L, 1)) {
        return original(L);
    }

    api.push_private_root(L);
    api._lua_pushstring(L, kPolicyKey);
    api._lua_rawget(L, -2);
    api._lua_remove(L, -2);
    if (api._lua_isfunction(L, -1)) {
        // No arguments, one result: the policy records the caller and answers the name (the
        // hook does not need it; attribution is the side effect).
        if (api._lua_pcall(L, 0, 1, 0) != 0) {
            // A ledger failure aborts the dump with the manager's own message, like before.
            api._lua_error(L);
            return 0;
        }
        api._lua_pop(L, 1);
    } else {
        api._lua_pop(L, 1);
    }
    // The policy must leave the dump arguments exactly as it found them.
    api._lua_settop(L, nargs);
    return original(L);
}

bool install_dump_attribution(CfunctionHook &hooks, LuaApis &api, lua_State *L) {
    if (!g_puc_dump_available) {
        return false;
    }
    // `hook_global` takes a global name; string.dump is a field of the string table.
    api._lua_getglobal(L, "string");
    if (!api._lua_istable(L, -1)) {
        api._lua_pop(L, 1);
        return false;
    }
    api._lua_getfield(L, -1, "dump");
    api._lua_remove(L, -2);
    const bool hooked = hooks.hook(api, L, -1, &dump_attribution_policy, nullptr);
    api._lua_pop(L, 1);
    return hooked;
}

} // namespace ds::core_vm::detail
