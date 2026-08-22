#pragma once
// Process-wide named service table (plugin discovery).
// Preferred API (auto schema from Fn):
//   host->register_service("name", &fn);
//   auto *fn = ds::plugin::request_service<decltype(&fn)>("name");
// Presence-only: lookup_service(name).

#include "config/InjectorHostConfig.hpp"
#include "GameInjectorLuaRegistry.hpp"
#include "GiTypeTraits.hpp"

#include <cstddef>
#include <string_view>
#include <type_traits>

namespace ds::plugin {

bool register_service(std::string_view name, const GiType *types, size_t ntypes, void *fn);
void *lookup_service(std::string_view name);
void *lookup_service_typed(std::string_view name, const GiType *types, size_t ntypes);

template <size_t N>
inline bool register_service(std::string_view name, const GiType (&types)[N], void *fn) {
    static_assert(N >= 1 && N <= kGiMaxTypes, "service GiType length");
    return register_service(name, types, N, fn);
}

} // namespace ds::plugin

DONTSTARVEINJECTOR_API void *ds_host_lookup_service(const char *name);
DONTSTARVEINJECTOR_API void *ds_host_lookup_service_typed(const char *name,
                                                           const ds::plugin::GiType *types,
                                                           size_t ntypes);

namespace ds::plugin {

// Auto-deduce GiType[] from function pointer type.
template <class Fn>
inline bool register_service(std::string_view name, Fn fn) {
    using Sig = GiSignature<Fn>;
    return register_service(name, Sig::types, Sig::ntypes, reinterpret_cast<void *>(fn));
}

template <class Fn>
inline Fn request_service(const char *name) {
    using Sig = GiSignature<Fn>;
    return reinterpret_cast<Fn>(ds_host_lookup_service_typed(name, Sig::types, Sig::ntypes));
}

template <class Fn>
struct ServiceDesc {
    using fn_type = Fn;
    using Sig = GiSignature<Fn>;
    const char *name;
    constexpr explicit ServiceDesc(const char *n) : name(n) {}
    Fn request() const { return request_service<Fn>(name); }
};

} // namespace ds::plugin
