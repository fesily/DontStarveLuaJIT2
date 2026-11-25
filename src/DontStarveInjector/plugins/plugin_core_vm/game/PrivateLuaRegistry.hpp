#pragma once
// game/PrivateLuaRegistry.hpp — the private root of one VM context.
//
// The key is the LuaApis instance: PUC 5.1 stores a C holder at registry[&api], while LuaJIT
// exposes the root through the second registry (LUA_REGISTRYINDEX2). The LuaApis address is the
// only handle; no per-state key/token is kept in this module.
#include "game/GameLuaContext.hpp"

namespace ds::core_vm::detail {
class GameLuaPrivateRegistry {
public:
    virtual ~GameLuaPrivateRegistry() = default;

    // Pushes the root for `context`. A broken invariant terminates the process; this is never
    // routed back to Lua.
    virtual void push(lua_State *L) = 0;

    // Creates/validates the private root keyed by `api` and returns the implementation for
    // `type`'s VM mode (PUC 5.1 holder or LuaJIT registry2). Leaves the stack unchanged. A
    // broken invariant terminates the process.
    // The caller owns the returned object (GameLuaContextImpl keeps it for the state lifetime).
    static GameLuaPrivateRegistry *initialize(LuaApis &api, GameLuaType type, lua_State *L);

protected:
    explicit GameLuaPrivateRegistry(LuaApis &api)
        : api(api) {
    }

    void *key() {
        return &api;
    }
    LuaApis &api;
};
} // namespace ds::core_vm::detail
