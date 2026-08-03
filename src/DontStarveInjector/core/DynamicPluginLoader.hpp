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

    DynamicLoadReport load_all(PluginHost &host);
    // Test seam: scan a single directory.
    DynamicLoadReport load_directory(PluginHost &host, const std::filesystem::path &dir);

    static std::vector<std::filesystem::path> default_search_dirs();

private:
    std::vector<void *> handles_; // HMODULE / void*
};

} // namespace ds::plugin
