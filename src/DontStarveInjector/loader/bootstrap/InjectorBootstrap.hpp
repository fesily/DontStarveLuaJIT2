#pragma once
#include <filesystem>
#include <string>
#include <vector>

namespace ds::bootstrap {

inline constexpr const char *kInjectorFileEnv = "DS_LUAJIT_INJECTOR";
inline constexpr const char *kInjectorDirEnv  = "DS_LUAJIT_INJECTOR_DIR";
inline constexpr const char *kMarkerFileName  = "ds_luajit_injector.path";

// Platform real-module file name (not the game stub).
// Windows: "Injector.dll"
// Linux:   "libInjector.so"
// macOS:   "libInjector.dylib"
const char *injector_module_filename();

// Resolve absolute path to the real Injector module file.
// Order: env file -> env dir -> marker -> mod scan -> legacy game bin64.
// Does not load the module. Returns false if nothing found.
bool resolve_injector_module(std::filesystem::path &out_abs);

// After non-legacy success, write marker under game data/unsafedata/.
// Exposed for tests; resolve may call this internally after success.
bool write_injector_marker(const std::filesystem::path &abs_module);

// Read marker path if file exists and points at an existing regular file.
bool read_injector_marker(std::filesystem::path &out_abs);

using HookStartupEntryFn = bool (*)();

// Resolve, configure deps search for mod_root/deps, LoadLibraryEx/dlopen,
// return HookStartupEntry or nullptr. Logs on failure.
HookStartupEntryFn load_injector_hook_entry();

// Derive mod_root from absolute module path:
//   .../mod/Injector.dll                  -> .../mod   (canonical)
//   .../mod/libInjector.so|.dylib         -> .../mod   (canonical)
//   .../mod/bin64/Injector.dll            -> .../mod   (legacy)
//   .../mod/bin64/lib64/libInjector.so    -> .../mod   (legacy)
std::filesystem::path mod_root_from_injector_module(const std::filesystem::path &abs_module);

// Windows: AddDllDirectory(mod_root/deps) if exists; AddDllDirectory(module parent).
// Non-Windows: no-op true (RPATH). Idempotent bookkeeping like PluginPath.
bool configure_injector_deps_search(const std::filesystem::path &mod_root,
                                    const std::filesystem::path &module_dir);


// --- Test seams (always available; no-ops / empty outside tests is fine) ---
void reset_for_test();
// Override game root used for marker path: game_root / data / unsafedata / marker.
// Empty clears override (production uses getExePath().parent_path().parent_path()).
void set_marker_game_root_for_test(const std::filesystem::path &game_root_or_empty);
// Override exe directory used for scan bases (production: getExePath().parent_path()).
void set_exe_dir_for_test(const std::filesystem::path &exe_dir_or_empty);
// Override cmdline tokens for -ugc_directory (production: get_cmds()).
void set_cmdline_for_test(std::vector<std::string> args_or_empty);
// When true, next successful resolve treats path as legacy (no marker write).
// Prefer automatic classification: path under test exe_dir counts as legacy.
// Document: production classifies "next to exe" as legacy.

// Optional: expose last resolve source for asserts: "env_file"|"env_dir"|"marker"|"scan"|"legacy"|"".
std::string last_resolve_source_for_test();

} // namespace ds::bootstrap
