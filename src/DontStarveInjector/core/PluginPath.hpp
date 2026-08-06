#pragma once
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin {

// Env override name (single source of truth).
inline constexpr const char *kPluginDirEnv = "DS_LUAJIT_PLUGIN_DIR";

// parent(modmain_path) / "plugins". Empty modmain_path → empty path.
std::filesystem::path plugins_dir_from_modmain(std::string_view modmain_path);

// If module_dir already ends with "plugins", return it; else module_dir / "plugins".
std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir);

// Directory of the module containing this code (Injector or static test image).
std::filesystem::path injector_module_dir();

// Resolve modmain_path: non-empty test override, optional provider, else empty.
// Task 2 registers the production provider that reads luajit_config.
std::string resolve_modmain_path();

// Optional production hook (Task 2). nullptr → empty when no test override.
using ModmainPathProvider = std::string (*)();
void set_modmain_path_provider(ModmainPathProvider fn);

// Test seam: empty clears override.
void set_modmain_path_override_for_test(std::string_view path_or_empty);

// Search roots in priority order, existing dirs only, weakly-canonical deduped:
//   1) DS_LUAJIT_PLUGIN_DIR if set and is a directory
//   2) plugins_dir_from_modmain(resolve_modmain_path()) if non-empty and is dir
//   3) plugins_dir_from_module_dir(injector_module_dir()) if non-empty and is dir
std::vector<std::filesystem::path> default_plugin_search_dirs();

// deps path for a plugins root: root / "deps"
std::filesystem::path plugins_deps_dir(const std::filesystem::path &plugins_root);

// Windows: once per process set default dirs policy; for each plugins root,
// AddDllDirectory(root/deps) if exists, optionally AddDllDirectory(root).
// Idempotent: repeated calls with same absolute paths no-op.
// Non-Windows: no-op success (RPATH is link-time).
// Returns true if no hard failure; missing deps dir is OK (not an error).
bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots);

// Test seam: clear internal "already added" set (Windows) between tests.
void reset_plugin_dll_search_for_test();

} // namespace ds::plugin
