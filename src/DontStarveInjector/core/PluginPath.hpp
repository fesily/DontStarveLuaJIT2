#pragma once
#include "config/InjectorHostConfig.hpp" // DS_INJECTOR_CXX_API
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin {

// Env override name (single source of truth).
inline constexpr const char *kPluginDirEnv = "DS_LUAJIT_PLUGIN_DIR";

// parent(modmain_path) / "plugins". Empty modmain_path → empty path.
DS_INJECTOR_CXX_API std::filesystem::path plugins_dir_from_modmain(std::string_view modmain_path);

// If module_dir already ends with "plugins", return it; else module_dir / "plugins".
DS_INJECTOR_CXX_API std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir);

// Directory of the module containing this code (Injector or static test image).
// When imported from a plugin DLL, this still resolves to Injector's directory
// because the definition lives in Injector.dll (process-wide shared state).
DS_INJECTOR_CXX_API std::filesystem::path injector_module_dir();

// Resolve modmain_path: non-empty test override, optional provider, else empty.
// Task 2 registers the production provider that reads luajit_config.
DS_INJECTOR_CXX_API std::string resolve_modmain_path();

// Optional production hook (Task 2). nullptr → empty when no test override.
using ModmainPathProvider = std::string (*)();
DS_INJECTOR_CXX_API void set_modmain_path_provider(ModmainPathProvider fn);

// Test seam: empty clears override.
DS_INJECTOR_CXX_API void set_modmain_path_override_for_test(std::string_view path_or_empty);

// Search roots in priority order, existing dirs only, weakly-canonical deduped:
//   1) DS_LUAJIT_PLUGIN_DIR if set and is a directory
//   2) plugins_dir_from_modmain(resolve_modmain_path()) if non-empty and is dir
//   3) plugins_dir_from_module_dir(injector_module_dir()) if non-empty and is dir
//
// Process-wide: provider/override/DLL-search bookkeeping live in Injector only.
// Plugins (e.g. plugin_manager) must import these symbols — do not compile
// PluginPath.cpp into another image or modmain registration is invisible.
DS_INJECTOR_CXX_API std::vector<std::filesystem::path> default_plugin_search_dirs();

// deps path for a plugins root: root / "deps"
DS_INJECTOR_CXX_API std::filesystem::path plugins_deps_dir(const std::filesystem::path &plugins_root);

// Windows: once per process set default dirs policy; for each plugins root,
// AddDllDirectory(root/deps) if exists, optionally AddDllDirectory(root).
// Idempotent: repeated calls with same absolute paths no-op.
// Non-Windows: no-op success (RPATH is link-time).
// Returns true if no hard failure; missing deps dir is OK (not an error).
DS_INJECTOR_CXX_API bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots);

// Test seam: clear internal "already added" set (Windows) between tests.
DS_INJECTOR_CXX_API void reset_plugin_dll_search_for_test();

} // namespace ds::plugin
