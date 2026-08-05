#include "GameInjectorLuaRegistry.hpp"

#include <cstring>
#include <mutex>
#include <string>
#include <vector>

namespace {

struct Entry {
    std::string name;
    ds::plugin::GiType types[ds::plugin::kGiMaxTypes]{};
    uint8_t ntypes = 0;
    void *fn = nullptr;
};

std::mutex g_mu;
std::vector<Entry> g_exports;

} // namespace

namespace ds::plugin {

bool register_game_injector_export(const char *name, const GiType *types, size_t ntypes, void *fn) {
    if (!name || !name[0] || !fn || !types || ntypes < 1 || ntypes > kGiMaxTypes) {
        return false;
    }
    // LuaCFunction must be alone.
    if (types[0] == GiType::LuaCFunction && ntypes != 1) {
        return false;
    }
    std::lock_guard lock(g_mu);
    for (const auto &e : g_exports) {
        if (e.name == name) {
            return false;
        }
    }
    Entry ent;
    ent.name = name;
    ent.ntypes = static_cast<uint8_t>(ntypes);
    ent.fn = fn;
    std::memcpy(ent.types, types, ntypes * sizeof(GiType));
    g_exports.push_back(std::move(ent));
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
        const auto &e = g_exports[static_cast<size_t>(i)];
        out[i].name = e.name.c_str();
        out[i].ntypes = e.ntypes;
        out[i].fn = e.fn;
        std::memcpy(out[i].types, e.types, e.ntypes * sizeof(GiType));
    }
    return n;
}

} // namespace ds::plugin

DONTSTARVEINJECTOR_API int ds_copy_game_injector_exports(ds::plugin::GameInjectorExport *out, int max) {
    return ds::plugin::copy_game_injector_exports(out, max);
}
