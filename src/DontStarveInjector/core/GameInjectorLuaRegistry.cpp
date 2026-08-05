#include "GameInjectorLuaRegistry.hpp"

#include <mutex>
#include <string>
#include <vector>

namespace {

struct Entry {
    std::string name;
    ds::plugin::GiSig sig = ds::plugin::GiSig::V_void;
    void *fn = nullptr;
};

std::mutex g_mu;
std::vector<Entry> g_exports;

} // namespace

namespace ds::plugin {

bool register_game_injector_export(const char *name, GiSig sig, void *fn) {
    if (!name || !name[0] || !fn) {
        return false;
    }
    std::lock_guard lock(g_mu);
    for (const auto &e : g_exports) {
        if (e.name == name) {
            return false;
        }
    }
    g_exports.push_back(Entry{std::string{name}, sig, fn});
    return true;
}

int copy_game_injector_exports(GameInjectorExport *out, int max) {
    std::lock_guard lock(g_mu);
    const int n = static_cast<int>(g_exports.size());
    if (!out || max <= 0) {
        return n;
    }
    const int write = n < max ? n : max;
    for (int i = 0; i < write; ++i) {
        out[i].name = g_exports[static_cast<size_t>(i)].name.c_str();
        out[i].sig = g_exports[static_cast<size_t>(i)].sig;
        out[i].fn = g_exports[static_cast<size_t>(i)].fn;
    }
    return n;
}

} // namespace ds::plugin

DONTSTARVEINJECTOR_API int ds_copy_game_injector_exports(ds::plugin::GameInjectorExport *out, int max) {
    return ds::plugin::copy_game_injector_exports(out, max);
}
