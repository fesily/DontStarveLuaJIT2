#pragma once
#include "config/InjectorHostConfig.hpp" // DS_INJECTOR_CXX_API
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin {

// Env override name (single source of truth).
inline constexpr const char *kPluginDirEnv = "DS_LUAJIT_PLUGIN_DIR";

// If module_dir already ends with "plugins", return it; else module_dir / "plugins".
DS_INJECTOR_CXX_API std::filesystem::path plugins_dir_from_module_dir(const std::filesystem::path &module_dir);

// Directory of the module containing this code (Injector or static test image).
// When imported from a plugin DLL, this still resolves to Injector's directory
// because the definition lives in Injector.dll (process-wide shared state).
DS_INJECTOR_CXX_API std::filesystem::path injector_module_dir();

// Test seam: override injector_module_dir(); empty clears.
DS_INJECTOR_CXX_API void set_injector_module_dir_for_test(
    const std::filesystem::path &module_dir_or_empty);

// The single plugin root this process uses. Exactly zero or one element:
//   1) DS_LUAJIT_PLUGIN_DIR when set to a non-empty value (must name an
//      existing directory; Windows reads the wide environment, POSIX UTF-8)
//   2) plugins_dir_from_module_dir(injector_module_dir()) when it exists
// No modmain/config, game-mods or UGC fallback: the tree that supplied the
// Injector module owns its plugins/. An empty result means the runtime has no
// plugins tree and must report that instead of scanning somewhere else.
// Weakly-canonicalized (relative values therefore resolve against the CWD at
// call time — prefer absolute); callers that need "the" root use .front().
//
// Process-wide: override/DLL-search bookkeeping live in Injector only.
// Plugins (e.g. plugin_manager) must import these symbols — do not compile
// PluginPath.cpp into another image or the resolved root forks per module.
DS_INJECTOR_CXX_API std::vector<std::filesystem::path> default_plugin_search_dirs();

// Derive mod root from a plugins directory: leaf "plugins" → parent,
// otherwise treat plugins_dir itself as the root (env override may be bare).
DS_INJECTOR_CXX_API std::filesystem::path mod_root_from_plugins_dir(const std::filesystem::path &plugins_dir);

// Lua-face packages directly under plugins_dir: entries whose name starts with
// "plugin_" and that contain modinfo.lua (the package marker the Lua loader
// needs). Sorted; missing/empty dir → {}. Paths are UTF-8 (as handed to us by
// the Lua sandbox). This is the single source of truth the Lua registry uses
// instead of a hand-written list, so a package that is not installed is never
// referenced.
DS_INJECTOR_CXX_API std::vector<std::string> list_plugin_packages(std::string_view plugins_dir_utf8);

// Same listing, but native-root first: when default_plugin_search_dirs()
// resolves, that single root is listed (exactly what the native loader loads).
// The hint (MODROOT .. "plugins/") is an engine path that need not exist for a
// Workshop item loaded from Steam UGC, so it is only consulted when no native
// root resolves. Deduped and sorted.
DS_INJECTOR_CXX_API std::vector<std::string> list_installed_plugin_packages(std::string_view plugins_dir_utf8);

// Shared runtimes path: mod_root / "deps" (sibling of plugins/, not under it).
DS_INJECTOR_CXX_API std::filesystem::path mod_deps_dir(const std::filesystem::path &mod_root);

// Registers library search roots for a plugins root: <mod>/deps (canonical),
// <plugins_root>/deps (legacy) and <plugins_root> (private side-by-side deps).
// Windows: AddDllDirectory each existing root (LoadLibraryEx is called with
// USER_DIRS | DLL_LOAD_DIR | DEFAULT_DIRS; process-wide SetDefaultDllDirectories
// is intentionally NOT used).
// Non-Windows: records the same roots in a process-wide registry that
// util/platform.cpp loadlib() consults. This is what keeps VM/dependency
// resolution working for plugins living OUTSIDE the mod tree — the caller
// passes the absolute directory it actually loaded from.
// Idempotent: repeated calls with same absolute paths no-op.
// Returns true if no hard failure; missing deps dir is OK (not an error).
DS_INJECTOR_CXX_API bool configure_plugin_dll_search(const std::vector<std::filesystem::path> &plugins_roots);

// Every root registered by configure_plugin_dll_search(), in registration order,
// absolute and deduped. loadlib() prioritises these after its own module dir.
// Windows also mirrors the list here for diagnostics; there the OS-side
// AddDllDirectory list is what actually drives LoadLibraryEx.
DS_INJECTOR_CXX_API std::vector<std::filesystem::path> plugin_dll_search_roots();

// Test seam: clear internal "already added" set (Windows) between tests.
DS_INJECTOR_CXX_API void reset_plugin_dll_search_for_test();

} // namespace ds::plugin
