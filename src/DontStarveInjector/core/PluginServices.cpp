#include "PluginServices.hpp"

#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace {

struct ServiceEntry {
    void *fn = nullptr;
    ds::plugin::GiType types[ds::plugin::kGiMaxTypes]{};
    uint8_t ntypes = 0;
};

std::mutex g_mu;
std::unordered_map<std::string, ServiceEntry> g_services;

bool types_equal(const ds::plugin::GiType *a, size_t na, const ds::plugin::GiType *b, size_t nb) {
    if (na != nb) {
        return false;
    }
    return std::memcmp(a, b, na * sizeof(ds::plugin::GiType)) == 0;
}

} // namespace

namespace ds::plugin {

bool register_service(std::string_view name, const GiType *types, size_t ntypes, void *fn) {
    if (name.empty() || !fn || !types || ntypes < 1 || ntypes > kGiMaxTypes) {
        return false;
    }
    std::lock_guard lock(g_mu);
    auto [it, inserted] = g_services.try_emplace(std::string(name));
    if (!inserted) {
        return false;
    }
    it->second.fn = fn;
    it->second.ntypes = static_cast<uint8_t>(ntypes);
    std::memcpy(it->second.types, types, ntypes * sizeof(GiType));
    return true;
}

void *lookup_service(std::string_view name) {
    if (name.empty()) {
        return nullptr;
    }
    std::lock_guard lock(g_mu);
    auto it = g_services.find(std::string(name));
    if (it == g_services.end()) {
        return nullptr;
    }
    return it->second.fn;
}

void *lookup_service_typed(std::string_view name, const GiType *types, size_t ntypes) {
    if (name.empty() || !types || ntypes < 1 || ntypes > kGiMaxTypes) {
        return nullptr;
    }
    std::lock_guard lock(g_mu);
    auto it = g_services.find(std::string(name));
    if (it == g_services.end()) {
        return nullptr;
    }
    if (!types_equal(it->second.types, it->second.ntypes, types, ntypes)) {
        return nullptr; // schema mismatch
    }
    return it->second.fn;
}

} // namespace ds::plugin

DONTSTARVEINJECTOR_API void *ds_host_lookup_service(const char *name) {
    if (!name) {
        return nullptr;
    }
    return ds::plugin::lookup_service(name);
}

DONTSTARVEINJECTOR_API void *ds_host_lookup_service_typed(const char *name,
                                                          const ds::plugin::GiType *types,
                                                          size_t ntypes) {
    if (!name) {
        return nullptr;
    }
    return ds::plugin::lookup_service_typed(name, types, ntypes);
}
