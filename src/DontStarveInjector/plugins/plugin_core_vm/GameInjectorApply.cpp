#include "GameLua.hpp"
#include "core/GameInjectorLuaRegistry.hpp"

#include <vector>

// NetSimStats layout must match plugin_network_sim (C ABI).
struct NetSimStats {
    bool     enabled;
    uint32_t delay_ms;
    uint32_t jitter_ms;
    uint32_t loss_pct;
    uint64_t packets_total;
    uint64_t packets_delayed;
    uint64_t packets_dropped;
    uint64_t packets_released;
    uint32_t queue_depth;
};

namespace {

using ds::plugin::GiSig;

LuaApis &A() {
    return GetGameLuaContext().api;
}

void *up_fn(lua_State *L) {
    return A()._lua_touserdata(L, lua_upvalueindex(1));
}

// --- trampolines: upvalue[1] = native fn ---

static int t_V_Bool(lua_State *L) {
    auto *fn = reinterpret_cast<void (*)(bool)>(up_fn(L));
    if (fn) fn(A()._lua_toboolean(L, 1) != 0);
    return 0;
}
static int t_V_I32(lua_State *L) {
    auto *fn = reinterpret_cast<void (*)(int)>(up_fn(L));
    if (fn) fn((int)A()._luaL_checkinteger(L, 1));
    return 0;
}
static int t_V_void(lua_State *L) {
    (void) L;
    auto *fn = reinterpret_cast<void (*)()>(up_fn(L));
    if (fn) fn();
    return 0;
}
static int t_I32_I32_I32(lua_State *L) {
    auto *fn = reinterpret_cast<int (*)(int, int)>(up_fn(L));
    if (!fn) {
        A()._lua_pushinteger(L, -1);
        return 1;
    }
    A()._lua_pushinteger(L, fn((int)A()._luaL_checkinteger(L, 1), (int)A()._luaL_checkinteger(L, 2)));
    return 1;
}
static int t_I32_I8_I8_Bool(lua_State *L) {
    auto *fn = reinterpret_cast<int (*)(char, char, bool)>(up_fn(L));
    if (!fn) {
        A()._lua_pushinteger(L, 0);
        return 1;
    }
    A()._lua_pushinteger(L, fn((char)A()._luaL_checkinteger(L, 1), (char)A()._luaL_checkinteger(L, 2),
                               A()._lua_toboolean(L, 3) != 0));
    return 1;
}
static int t_CString_void(lua_State *L) {
    auto *fn = reinterpret_cast<const char *(*)()>(up_fn(L));
    const char *s = fn ? fn() : nullptr;
    if (s) A()._lua_pushstring(L, s); else A()._lua_pushnil(L);
    return 1;
}
static int t_V_U32_U32_U32(lua_State *L) {
    auto *fn = reinterpret_cast<void (*)(uint32_t, uint32_t, uint32_t)>(up_fn(L));
    if (fn) {
        fn((uint32_t)A()._luaL_checkinteger(L, 1), (uint32_t)A()._luaL_checkinteger(L, 2),
           (uint32_t)A()._luaL_checkinteger(L, 3));
    }
    return 0;
}
static int t_Ptr_Ptr_I64(lua_State *L) {
    auto *fn = reinterpret_cast<void *(*)(void *, int64_t)>(up_fn(L));
    if (!fn) {
        A()._lua_pushnil(L);
        return 1;
    }
    void *p = A()._lua_touserdata(L, 1);
    const int64_t id = (int64_t)A()._luaL_checknumber(L, 2);
    void *r = fn(p, id);
    if (r) A()._lua_pushlightuserdata(L, r); else A()._lua_pushnil(L);
    return 1;
}
static int t_V_OptI32x3(lua_State *L) {
    // SetNextRpcInfo: three optional ints. Pack as optional via sentinel path:
    // Call native as void(*)(int has0,int v0, int has1,int v1, int has2,int v2) is awkward.
    // Actual service is optional-based C++ — we cannot call it without knowing ABI.
    // Instead require the service to be a C ABI:
    //   void (*)(const int *p0, const int *p1, const int *p2)  with null = absent
    using Fn = void (*)(const int *, const int *, const int *);
    auto *fn = reinterpret_cast<Fn>(up_fn(L));
    if (!fn) return 0;
    int v0 = 0, v1 = 0, v2 = 0;
    const int *p0 = nullptr, *p1 = nullptr, *p2 = nullptr;
    if (!A()._lua_isnoneornil(L, 1)) { v0 = (int)A()._luaL_checkinteger(L, 1); p0 = &v0; }
    if (!A()._lua_isnoneornil(L, 2)) { v1 = (int)A()._luaL_checkinteger(L, 2); p1 = &v1; }
    if (!A()._lua_isnoneornil(L, 3)) { v2 = (int)A()._luaL_checkinteger(L, 3); p2 = &v2; }
    fn(p0, p1, p2);
    return 0;
}
static int t_I32_void(lua_State *L) {
    auto *fn = reinterpret_cast<int (*)()>(up_fn(L));
    A()._lua_pushinteger(L, fn ? fn() : 0);
    return 1;
}
static int t_Bool_Bool(lua_State *L) {
    auto *fn = reinterpret_cast<bool (*)(bool)>(up_fn(L));
    const bool r = fn ? fn(A()._lua_toboolean(L, 1) != 0) : false;
    A()._lua_pushboolean(L, r ? 1 : 0);
    return 1;
}
static int t_Table_NetSimStats(lua_State *L) {
    using Fn = const NetSimStats *(*)();
    auto *fn = reinterpret_cast<Fn>(up_fn(L));
    A()._lua_newtable(L);
    const NetSimStats *s = fn ? fn() : nullptr;
    if (!s) return 1;
    auto seti = [&](const char *k, lua_Integer v) {
        A()._lua_pushinteger(L, v);
        A()._lua_setfield(L, -2, k);
    };
    A()._lua_pushboolean(L, s->enabled ? 1 : 0);
    A()._lua_setfield(L, -2, "enabled");
    seti("delay_ms", s->delay_ms);
    seti("jitter_ms", s->jitter_ms);
    seti("loss_pct", s->loss_pct);
    seti("packets_total", (lua_Integer)s->packets_total);
    seti("packets_delayed", (lua_Integer)s->packets_delayed);
    seti("packets_dropped", (lua_Integer)s->packets_dropped);
    seti("packets_released", (lua_Integer)s->packets_released);
    seti("queue_depth", (lua_Integer)s->queue_depth);
    return 1;
}

lua_CFunction trampoline_for(GiSig sig) {
    switch (sig) {
    case GiSig::V_Bool: return &t_V_Bool;
    case GiSig::V_I32: return &t_V_I32;
    case GiSig::V_void: return &t_V_void;
    case GiSig::I32_I32_I32: return &t_I32_I32_I32;
    case GiSig::I32_I8_I8_Bool: return &t_I32_I8_I8_Bool;
    case GiSig::CString_void: return &t_CString_void;
    case GiSig::V_U32_U32_U32: return &t_V_U32_U32_U32;
    case GiSig::Ptr_Ptr_I64: return &t_Ptr_Ptr_I64;
    case GiSig::V_OptI32x3: return &t_V_OptI32x3;
    case GiSig::Table_NetSimStats: return &t_Table_NetSimStats;
    case GiSig::LuaCFunction: return nullptr; // special
    case GiSig::I32_void: return &t_I32_void;
    case GiSig::Bool_Bool: return &t_Bool_Bool;
    }
    return nullptr;
}

} // namespace

namespace ds::core_vm {

// Bind all registered exports onto the table currently at stack abs index `table_idx`.
void apply_game_injector_exports(lua_State *L, int table_idx) {
    auto &api = GetGameLuaContext().api;
    table_idx = api._lua_absindex(L, table_idx);

    const int n = ds_copy_game_injector_exports(nullptr, 0);
    if (n <= 0) {
        return;
    }
    std::vector<ds::plugin::GameInjectorExport> exports(static_cast<size_t>(n));
    ds_copy_game_injector_exports(exports.data(), n);

    for (const auto &e : exports) {
        if (!e.name || !e.fn) {
            continue;
        }
        if (e.sig == GiSig::LuaCFunction) {
            api._lua_pushcfunction(L, reinterpret_cast<lua_CFunction>(e.fn));
            api._lua_setfield(L, table_idx, e.name);
            continue;
        }
        auto *tri = trampoline_for(e.sig);
        if (!tri) {
            continue;
        }
        api._lua_pushlightuserdata(L, e.fn);
        api._lua_pushcclosure(L, tri, 1);
        api._lua_setfield(L, table_idx, e.name);
    }
}

} // namespace ds::core_vm
