#pragma once
// Process-wide named service table (plugin discovery).
// Write: PluginHost::register_service(name, GiType[], fn) in module_init window.
// Read:  ServiceDesc / request_service — schema must match or nullptr.
// Presence-only: lookup_service(name) for resolve gates / inject.

#include "config/InjectorHostConfig.hpp"
#include "GameInjectorLuaRegistry.hpp" // GiType, kGiMaxTypes

#include <cstddef>
#include <string_view>

namespace ds::plugin {

bool register_service(std::string_view name, const GiType *types, size_t ntypes, void *fn);
void *lookup_service(std::string_view name);
void *lookup_service_typed(std::string_view name, const GiType *types, size_t ntypes);

} // namespace ds::plugin

// Exported for MODULE plugins (request path).
DONTSTARVEINJECTOR_API void *ds_host_lookup_service(const char *name);
DONTSTARVEINJECTOR_API void *ds_host_lookup_service_typed(const char *name,
                                                           const ds::plugin::GiType *types,
                                                           size_t ntypes);

namespace ds::plugin {

template <size_t N>
inline bool register_service(std::string_view name, const GiType (&types)[N], void *fn) {
    static_assert(N >= 1 && N <= kGiMaxTypes, "service GiType length");
    return register_service(name, types, N, fn);
}

// Typed request with schema check (mismatch / missing → nullptr).
template <class Fn, size_t N>
inline Fn request_service(const char *name, const GiType (&types)[N]) {
    static_assert(N >= 1 && N <= kGiMaxTypes, "service GiType length");
    return reinterpret_cast<Fn>(ds_host_lookup_service_typed(name, types, N));
}

// One descriptor: shared name + schema for register & request.
//   static constexpr ServiceDesc<float(*)(), GiType::F32> kFrameTime{"DS_LUAJIT_get_frame_time_s"};
//   host->register_service(kFrameTime.name, kFrameTime.types, &fn);
//   if (auto *fn = kFrameTime.request()) fn();
template <class Fn, GiType... Types>
struct ServiceDesc {
    static_assert(sizeof...(Types) >= 1 && sizeof...(Types) <= kGiMaxTypes, "ServiceDesc arity");
    using fn_type = Fn;
    static constexpr GiType types[sizeof...(Types)] = {Types...};
    static constexpr size_t ntypes = sizeof...(Types);
    const char *name;
    constexpr explicit ServiceDesc(const char *n) : name(n) {}

    Fn request() const {
        return reinterpret_cast<Fn>(ds_host_lookup_service_typed(name, types, ntypes));
    }
};

} // namespace ds::plugin
