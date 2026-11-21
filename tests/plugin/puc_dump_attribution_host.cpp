// tests/plugin/puc_dump_attribution_host.cpp
//
// Bridge between the dual-VM dump host (tests/plugin/puc_dump_host.cpp, which deliberately
// uses a minimal `void *lua_State` ABI and never includes the plugin's headers) and the
// production TUs that own string.dump attribution:
//   game/CfunctionHook.cpp    the closure-implementation hook service
//   game/DumpAttribution.cpp  the policy installed on `string.dump`
//   game/PrivateLuaRegistry.cpp  the private root the policy reads
//
// The dump host loads the VM at runtime; this TU resolves every lua_* entry into a real LuaApis
// from the same handle, binds the production private-root callbacks and installs the hook on a
// freshly opened state. What runs is the shipped policy, not a copy of it: if the VM-side
// callback ever comes back or the hook stops attributing, the Lua spec that drives this host
// fails its record assertions.
#include "game/CfunctionHook.hpp"
#include "game/DumpAttribution.hpp"
#include "game/PrivateLuaRegistry.hpp"

#include <cstdio>
#include <exception>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace {

void *find_symbol(void *handle, const char *name) {
#ifdef _WIN32
    return reinterpret_cast<void *>(GetProcAddress(static_cast<HMODULE>(handle), name));
#else
    return dlsym(handle, name);
#endif
}

struct HostContext : GameLuaContext {
    HostContext() : GameLuaContext{"puc-dump-attribution-host", GameLuaType::jit} {}
};

struct Bridge {
    LuaApis api{};
    HostContext context;
    ds::core_vm::detail::CfunctionHook hooks;
    bool api_ready{false};
};

Bridge &bridge() {
    static Bridge instance;
    return instance;
}

bool fill_api(Bridge &b, void *handle) {
#define DS_FILL(name) \
    b.api._##name = reinterpret_cast<decltype(&name)>(find_symbol(handle, #name));
    LUA51_API_DEFINES(DS_FILL);
    LUAJIT_API_DEFINES(DS_FILL);
    LUAJIT_API_DEFINES_5_2(DS_FILL);
    LUAJIT_API_DEFINES_5_3(DS_FILL);
#undef DS_FILL
    // The hook + private root + policy only need this subset, and a missing one would be a
    // null call in the middle of a dump.
    return b.api._lua_pushcclosure != nullptr && b.api._lua_tocfunction != nullptr &&
           b.api._lua_topointer != nullptr && b.api._lua_pushvalue != nullptr &&
           b.api._lua_rawget != nullptr && b.api._lua_pushlightuserdata != nullptr &&
           b.api._lua_pcall != nullptr && b.api._lua_error != nullptr &&
           b.api._lua_getupvalue != nullptr && b.api._lua_pushstring != nullptr &&
           b.api._lua_settop != nullptr && b.api._lua_gettop != nullptr &&
           b.api._lua_remove != nullptr && b.api._lua_createtable != nullptr &&
           b.api._lua_rawset != nullptr;
}

} // namespace

extern "C" int ds_host_install_dump_attribution(void *handle, void *state) {
    auto &b = bridge();
    try {
        if (!b.api_ready) {
            if (handle == nullptr || !fill_api(b, handle)) {
                std::fprintf(stderr, "[dump-attribution] cannot resolve the lua_* entries\n");
                return 0;
            }
            b.api.BindApiHooks(b.context);
            b.api_ready = true;
        }
        auto *L = static_cast<lua_State *>(state);
        if (b.context.privateRegistry == nullptr) {
            b.context.privateRegistry = ds::core_vm::detail::GameLuaPrivateRegistry::initialize(
                b.api, GameLuaType::jit, L);
            if (b.context.privateRegistry == nullptr) {
                std::fprintf(stderr, "[dump-attribution] private root unavailable\n");
                return 0;
            }
        }
        // The host only installs the hook when the loaded VM exposes the dump bridge (main()
        // checks the slot); mirror what core.vm publishes for the plugin.
        ds::core_vm::detail::set_puc_dump_available(true);
        return ds::core_vm::detail::install_dump_attribution(b.hooks, b.api, L) ? 1 : 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "[dump-attribution] install failed: %s\n", error.what());
        return 0;
    }
}
