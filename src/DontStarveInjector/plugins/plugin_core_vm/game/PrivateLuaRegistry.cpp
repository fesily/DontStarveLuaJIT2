// game/PrivateLuaRegistry.cpp — the two private-root implementations.
#include "game/PrivateLuaRegistry.hpp"
#include "game/InjectorFileHijack.hpp"

#include <fast_assert/fast_assert.hpp>
#include <exception>


void LuaApis::BindApiHooks(GameLuaContext &context) {
    parentContext = &context;
    _push_private_root = [](LuaApis &api, lua_State *L) {
        GameLuaContext &ctx = *api.parentContext;
        FAST_ASSUME(ctx.privateRegistry != nullptr);
        ctx.privateRegistry->push(L);
    };
    _push_game_injector = [](LuaApis &api, lua_State *L) {
        GameLuaContext &ctx = *api.parentContext;
        FAST_ASSUME(ctx.privateRegistry != nullptr);
        ctx.privateRegistry->push(L);
        api._lua_getfield(L, -1, GameLuaInjectorName);
        api._lua_remove(L, -2);
        FAST_ASSERT(api._lua_istable(L, -1));
    };
}

namespace ds::core_vm::detail {

namespace {

static bool registry2_mode(GameLuaType type) {
    return type == GameLuaType::jit || type == GameLuaType::jit_gen;
}

// PUC 5.1: the root is upvalue 1 of a C holder stored at registry[&api]. The holder is the
// only registry entry; the 5.1 debug library refuses C upvalues, so Lua cannot reach the table.
static int puc_root_holder(lua_State *L) {
    (void)L;
    return 0;
}

class Puc51Registry final : public GameLuaPrivateRegistry {
public:
    explicit Puc51Registry(LuaApis &api)
        : GameLuaPrivateRegistry(api) {
    }

    void push(lua_State *L) override {
        api._lua_pushlightuserdata(L, key());
        api._lua_rawget(L, LUA_REGISTRYINDEX);
        if (!api._lua_isfunction(L, -1)) {
            api._lua_pop(L, 1);
            FAST_PANIC();
        }
        if (api._lua_getupvalue(L, -1, 1) == nullptr) {
            api._lua_pop(L, 1);
            FAST_PANIC();
        }
        api._lua_remove(L, -2);  // holder; root stays on top
        if (!api._lua_istable(L, -1)) {
            api._lua_pop(L, 1);
            FAST_PANIC("private registry root is not a table");
        }
    }

    void create(lua_State *L) {
        api._lua_pushlightuserdata(L, key());
        api._lua_rawget(L, LUA_REGISTRYINDEX);
        if (api._lua_isfunction(L, -1)) {
            api._lua_pop(L, 1);
            return;
        }
        if (!api._lua_isnil(L, -1)) {
            api._lua_pop(L, 1);
            FAST_PANIC("private registry holder key is occupied");
        }
        api._lua_pop(L, 1);
        api._lua_createtable(L, 0, 0);                  // root
        api._lua_pushcclosure(L, &puc_root_holder, 1);  // holder with root as upvalue 1
        api._lua_pushlightuserdata(L, key());
        api._lua_pushvalue(L, -2);
        api._lua_rawset(L, LUA_REGISTRYINDEX);
        api._lua_pop(L, 1);                             // holder
    }
};

class Registry2Registry final : public GameLuaPrivateRegistry {
public:
    explicit Registry2Registry(LuaApis &api)
        : GameLuaPrivateRegistry(api) {
    }

    void push(lua_State *L) override {
        api._lua_pushvalue(L, LUA_REGISTRYINDEX2);
        if (!api._lua_istable(L, -1)) {
            api._lua_pop(L, 1);
            FAST_PANIC("LUA_REGISTRYINDEX2 is not a table");
        }
    }
};

} // namespace

GameLuaPrivateRegistry *GameLuaPrivateRegistry::initialize(LuaApis &api, GameLuaType type, lua_State *L) {
    if (L == nullptr) {
        FAST_PANIC("private registry initialized without a state");
    }
    if (registry2_mode(type)) {
        api._lua_pushvalue(L, LUA_REGISTRYINDEX2);
        if (!api._lua_istable(L, -1)) {
            api._lua_pop(L, 1);
            return nullptr;
        }
        api._lua_pop(L, 1);
        return new Registry2Registry(api);
    }
    auto *registry = new Puc51Registry(api);
    registry->create(L);
    return registry;
}

} // namespace ds::core_vm::detail
