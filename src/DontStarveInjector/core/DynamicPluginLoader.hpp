#pragma once

#include "PluginHost.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ds::plugin {

struct DynamicLoadReport {
    std::vector<std::string> loaded_modules; // absolute paths
    std::vector<std::string> skipped;        // path + reason short
};

// Loads plugin_* shared libraries from search dirs and invokes module init.
// Successful module handles are retained for process lifetime (never FreeLibrary).
class DynamicPluginLoader {
public:
    DynamicPluginLoader() = default;
    // Successful handles intentionally not closed (plugins may hold live vtables).
    ~DynamicPluginLoader();

    DynamicPluginLoader(const DynamicPluginLoader &) = delete;
    DynamicPluginLoader &operator=(const DynamicPluginLoader &) = delete;

    // is_client selects enabled-mod enumeration sources for external packs.
    DynamicLoadReport load_all(PluginHost &host, bool is_client = true);
    // Test seam: scan a single directory (built-in roots only).
    DynamicLoadReport load_directory(PluginHost &host, const std::filesystem::path &dir);

    // Load one module path (package or flat). Used by external discovery after trust gate.
    // On failure returns false and sets skip_reason when non-null.
    bool load_module_path(PluginHost &host, const std::filesystem::path &path,
                          std::string *skip_reason = nullptr);

    static std::vector<std::filesystem::path> default_search_dirs();

private:
    // Plugin stems this loader already handled (loaded or refused). Two search roots can
    // carry the same package (mod-local tree + the injector_module_dir() migration
    // fallback); initializing a second copy of one plugin re-registers its services and
    // crashes the host, so the first root wins per stem.
    std::vector<std::string> handled_stems_;
    std::vector<void *> handles_; // HMODULE / void *
};

} // namespace ds::plugin
