#pragma once
#include "config/InjectorHostConfig.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ds::plugin {

struct EnabledDstMod {
    std::string name; // folder or workshop- id as game uses
    std::filesystem::path root;
};

// Parse a DST modoverrides.lua / similar table return and collect names
// whose entry has enabled == true (missing enabled treated as false).
DS_INJECTOR_CXX_API std::vector<std::string>
parse_modoverrides_enabled_names(const std::filesystem::path &path);

// Role-aware enumeration. Server: cluster modoverrides paths when available.
// Client: best-effort modsettings + optional test seam via
// DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS (semicolon/path-list of absolute mod roots).
// Unresolved names are omitted.
DS_INJECTOR_CXX_API std::vector<EnabledDstMod> enumerate_enabled_dst_mods(bool is_client);

// Resolve a mod name to a filesystem root under known mods/UGC bases.
// Empty if not found. Exposed for tests.
DS_INJECTOR_CXX_API std::filesystem::path
resolve_dst_mod_root(const std::string &mod_name,
                     const std::vector<std::filesystem::path> &search_bases);

} // namespace ds::plugin
