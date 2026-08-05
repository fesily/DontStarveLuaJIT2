#pragma once
// GameInjector Lua export registry (L0 storage only — never calls lua_*).
// Plugins register (name, GiType[ret,args...], native_fn) in module_init.
// core.vm applies descriptors with a type-array trampoline (no per-shape enum explosion).

#include "config/InjectorHostConfig.hpp"

#include <cstdint>
#include <cstddef>

struct lua_State;

namespace ds::plugin {

// Scalar / special types used in GameInjector native exports.
// Signature = array: types[0] = return, types[1..] = parameters.
enum class GiType : uint8_t {
    Void = 0,
    Bool,
    I8,
    I32,
    U32,
    I64,
    F64,
    CString,       // const char*
    LightUserdata, // void*
    OptI32,        // optional int: nil → null const int* to native (C ABI)
    NetSimStats,   // const NetSimStats*(*)() → Lua table (core.vm pack)
    LuaCFunction,  // int(*)(lua_State*): install as-is; must be sole types[0]
};

inline constexpr size_t kGiMaxTypes = 1 + 8; // ret + up to 8 args

struct GameInjectorExport {
    const char *name = nullptr;
    GiType types[kGiMaxTypes]{};
    uint8_t ntypes = 0; // >= 1
    void *fn = nullptr;
};

// Window-gated write (PluginHost). types[0]=ret, types[1..ntypes)=args.
// ntypes must be in [1, kGiMaxTypes]. Copies the type array into registry storage.
bool register_game_injector_export(const char *name, const GiType *types, size_t ntypes, void *fn);

// Snapshot for core.vm (name/types point into registry storage until process exit).
int copy_game_injector_exports(GameInjectorExport *out, int max);

// Helper for brace-init at call sites: register_game_injector_export(host, "x", {GiType::I32, GiType::I32, GiType::I32}, fn)
template <size_t N>
inline bool register_game_injector_export(const char *name, const GiType (&types)[N], void *fn) {
    static_assert(N >= 1 && N <= kGiMaxTypes, "GiType signature length");
    return register_game_injector_export(name, types, N, fn);
}

} // namespace ds::plugin

DONTSTARVEINJECTOR_API int ds_copy_game_injector_exports(ds::plugin::GameInjectorExport *out, int max);
