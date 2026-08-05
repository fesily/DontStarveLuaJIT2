#pragma once
// GameInjector Lua export registry (L0 storage only — never calls lua_*).
// Plugins register (name, sig, native_fn) in module_init via PluginHost.
// core.vm applies descriptors in luaopen_GameInjector with table-driven trampolines.

#include "config/InjectorHostConfig.hpp"

#include <cstdint>

struct lua_State;

namespace ds::plugin {

// Fixed signature catalogue for auto trampolines (core.vm). Extend only when a
// new shape appears — no general reflection.
enum class GiSig : uint16_t {
    // void (*)(bool)
    V_Bool = 1,
    // void (*)(int)
    V_I32 = 2,
    // void (*)()
    V_void = 3,
    // int (*)(int, int)
    I32_I32_I32 = 4,
    // int (*)(char, char, bool)
    I32_I8_I8_Bool = 5,
    // const char *(*)()
    CString_void = 6,
    // void (*)(uint32_t, uint32_t, uint32_t)
    V_U32_U32_U32 = 7,
    // void *(*)(void *, int64_t)
    Ptr_Ptr_I64 = 8,
    // void (*)(opt i32, opt i32, opt i32)  — three optional ints (nil = absent)
    V_OptI32x3 = 9,
    // const NetSimStats *(*)() → Lua table (layout known to core.vm)
    Table_NetSimStats = 10,
    // int (*)(lua_State *) — install as lua_CFunction as-is
    LuaCFunction = 11,
    // int (*)()
    I32_void = 12,
    // bool (*)(bool)
    Bool_Bool = 13,
};

struct GameInjectorExport {
    const char *name = nullptr; // stable literal
    GiSig sig = GiSig::V_void;
    void *fn = nullptr;         // native pointer matching sig
};

// Window-gated write (PluginHost).
bool register_game_injector_export(const char *name, GiSig sig, void *fn);

// Snapshot for core.vm (names point into registry storage until process exit).
int copy_game_injector_exports(GameInjectorExport *out, int max);

} // namespace ds::plugin

DONTSTARVEINJECTOR_API int ds_copy_game_injector_exports(ds::plugin::GameInjectorExport *out, int max);
