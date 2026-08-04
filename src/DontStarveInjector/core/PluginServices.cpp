#include "PluginServices.hpp"

#include <mutex>
#include <string>
#include <unordered_map>

namespace {

std::mutex g_mu;
std::unordered_map<std::string, void *> g_services;

} // namespace

namespace ds::plugin {

bool register_service(std::string_view name, void *fn) {
    if (name.empty() || !fn) {
        return false;
    }
    std::lock_guard lock(g_mu);
    auto [it, inserted] = g_services.emplace(std::string(name), fn);
    (void) it;
    return inserted;
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
    return it->second;
}

} // namespace ds::plugin

DONTSTARVEINJECTOR_API bool ds_host_register_service(const char *name, void *fn) {
    if (!name) {
        return false;
    }
    return ds::plugin::register_service(name, fn);
}

DONTSTARVEINJECTOR_API void *ds_host_lookup_service(const char *name) {
    if (!name) {
        return nullptr;
    }
    return ds::plugin::lookup_service(name);
}
