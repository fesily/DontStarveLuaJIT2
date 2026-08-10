#include "GameLua.hpp"
#include "core/GameInjectorLuaRegistry.hpp"

#include <cstdint>
#include <cstring>
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

using ds::plugin::GiType;
using ds::plugin::kGiMaxTypes;

LuaApis &A() {
    return GetGameLuaContext().api;
}

// Upvalues: [1]=fn lightud, [2]=ntypes as integer, [3]=types blob lightud (heap copy)
// We store a heap descriptor owned until process exit (register-once).

struct SigBlob {
    GiType types[kGiMaxTypes]{};
    uint8_t ntypes = 0;
};

// Keep blobs alive (apply only runs after all modules registered; no free).
std::vector<SigBlob *> g_blobs;

void *up_fn(lua_State *L) {
    return A()._lua_touserdata(L, lua_upvalueindex(1));
}

const SigBlob *up_sig(lua_State *L) {
    return static_cast<const SigBlob *>(A()._lua_touserdata(L, lua_upvalueindex(2)));
}

// Win64 / SysV x64: pass integers/pointers in GPRs. We only support the types
// used by current plugins — packed as uint64_t slots, then call via a
// fixed-arity switch on argc (ret handled separately).

using U64 = uint64_t;

static U64 read_arg(lua_State *L, int idx, GiType t, int *opt_storage) {
    switch (t) {
    case GiType::Bool:
        return A()._lua_toboolean(L, idx) ? 1 : 0;
    case GiType::I8:
        return static_cast<U64>(static_cast<int8_t>(A()._luaL_checkinteger(L, idx)));
    case GiType::I32:
        return static_cast<U64>(static_cast<int32_t>(A()._luaL_checkinteger(L, idx)));
    case GiType::U32:
        return static_cast<U64>(static_cast<uint32_t>(A()._luaL_checkinteger(L, idx)));
    case GiType::I64:
        return static_cast<U64>(static_cast<int64_t>(A()._luaL_checknumber(L, idx)));
    case GiType::F32: {
        float f = static_cast<float>(A()._luaL_checknumber(L, idx));
        U64 bits = 0;
        std::memcpy(&bits, &f, sizeof(f));
        return bits;
    }
    case GiType::F64: {
        double d = A()._luaL_checknumber(L, idx);
        U64 bits = 0;
        static_assert(sizeof(double) == sizeof(U64));
        std::memcpy(&bits, &d, sizeof(d));
        return bits;
    }
    case GiType::CString:
        return reinterpret_cast<U64>(A()._luaL_checkstring(L, idx));
    case GiType::LightUserdata:
        return reinterpret_cast<U64>(A()._lua_touserdata(L, idx));
    case GiType::OptI32:
        // Native ABI: const int* (null if nil). Storage must outlive call.
        if (A()._lua_isnoneornil(L, idx)) {
            return 0;
        }
        *opt_storage = static_cast<int>(A()._luaL_checkinteger(L, idx));
        return reinterpret_cast<U64>(opt_storage);
    case GiType::Void:
    case GiType::NetSimStats:
    case GiType::LuaCFunction:
    default:
        return 0;
    }
}

// Call fn with 0..8 uint64 args (integer/pointer ABI). F64 passed as bits —
// only used if we add float args later on platforms matching this packing.
using Fn0 = U64 (*)();
using Fn1 = U64 (*)(U64);
using Fn2 = U64 (*)(U64, U64);
using Fn3 = U64 (*)(U64, U64, U64);
using Fn4 = U64 (*)(U64, U64, U64, U64);
using Fn5 = U64 (*)(U64, U64, U64, U64, U64);
using Fn6 = U64 (*)(U64, U64, U64, U64, U64, U64);
using Fn7 = U64 (*)(U64, U64, U64, U64, U64, U64, U64);
using Fn8 = U64 (*)(U64, U64, U64, U64, U64, U64, U64, U64);

static U64 call_u64(void *fn, const U64 *a, int n) {
    switch (n) {
    case 0: return reinterpret_cast<Fn0>(fn)();
    case 1: return reinterpret_cast<Fn1>(fn)(a[0]);
    case 2: return reinterpret_cast<Fn2>(fn)(a[0], a[1]);
    case 3: return reinterpret_cast<Fn3>(fn)(a[0], a[1], a[2]);
    case 4: return reinterpret_cast<Fn4>(fn)(a[0], a[1], a[2], a[3]);
    case 5: return reinterpret_cast<Fn5>(fn)(a[0], a[1], a[2], a[3], a[4]);
    case 6: return reinterpret_cast<Fn6>(fn)(a[0], a[1], a[2], a[3], a[4], a[5]);
    case 7: return reinterpret_cast<Fn7>(fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6]);
    case 8: return reinterpret_cast<Fn8>(fn)(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7]);
    default: return 0;
    }
}

static int push_ret(lua_State *L, GiType ret, U64 r, void *fn) {
    switch (ret) {
    case GiType::Void:
        return 0;
    case GiType::Bool:
        A()._lua_pushboolean(L, r ? 1 : 0);
        return 1;
    case GiType::I8:
    case GiType::I32:
    case GiType::U32:
        A()._lua_pushinteger(L, static_cast<lua_Integer>(r));
        return 1;
    case GiType::I64:
        A()._lua_pushnumber(L, static_cast<double>(static_cast<int64_t>(r)));
        return 1;
    case GiType::F32: {
        float f = 0;
        std::memcpy(&f, &r, sizeof(f));
        A()._lua_pushnumber(L, static_cast<double>(f));
        return 1;
    }
    case GiType::F64: {
        double d = 0;
        std::memcpy(&d, &r, sizeof(d));
        A()._lua_pushnumber(L, d);
        return 1;
    }
    case GiType::CString: {
        const char *s = reinterpret_cast<const char *>(r);
        if (s) A()._lua_pushstring(L, s); else A()._lua_pushnil(L);
        return 1;
    }
    case GiType::LightUserdata: {
        void *p = reinterpret_cast<void *>(r);
        if (p) A()._lua_pushlightuserdata(L, p); else A()._lua_pushnil(L);
        return 1;
    }
    case GiType::NetSimStats: {
        // Prefer return value if non-null; else treat as const NetSimStats*(*)().
        const NetSimStats *s = reinterpret_cast<const NetSimStats *>(r);
        if (!s && fn) {
            s = reinterpret_cast<const NetSimStats *(*)()>(fn)();
        }
        A()._lua_newtable(L);
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
    case GiType::OptI32:
    case GiType::LuaCFunction:
    default:
        return 0;
    }
}

static int generic_trampoline(lua_State *L) {
    void *fn = up_fn(L);
    const SigBlob *sig = up_sig(L);
    if (!fn || !sig || sig->ntypes < 1) {
        return 0;
    }
    const GiType ret = sig->types[0];
    const int argc = static_cast<int>(sig->ntypes) - 1;

    // Special: NetSimStats with 0 args — call as const NetSimStats*(*)()
    if (ret == GiType::NetSimStats && argc == 0) {
        return push_ret(L, ret, 0, fn);
    }

    U64 args[8]{};
    int opt_store[8]{};
    for (int i = 0; i < argc && i < 8; ++i) {
        args[i] = read_arg(L, i + 1, sig->types[static_cast<size_t>(i + 1)], &opt_store[i]);
    }
    const U64 r = call_u64(fn, args, argc);
    return push_ret(L, ret, r, fn);
}

} // namespace

namespace ds::core_vm {

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
        if (!e.name || !e.fn || e.ntypes < 1) {
            continue;
        }
        if (e.types[0] == GiType::LuaCFunction) {
            api._lua_pushcfunction(L, reinterpret_cast<lua_CFunction>(e.fn));
            api._lua_setfield(L, table_idx, e.name);
            continue;
        }
        auto *blob = new SigBlob{};
        blob->ntypes = e.ntypes;
        std::memcpy(blob->types, e.types, e.ntypes * sizeof(GiType));
        g_blobs.push_back(blob);

        api._lua_pushlightuserdata(L, e.fn);
        api._lua_pushlightuserdata(L, blob);
        api._lua_pushcclosure(L, &generic_trampoline, 2);
        api._lua_setfield(L, table_idx, e.name);
    }
}

} // namespace ds::core_vm
