#include "core/PluginPath.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

namespace fs = std::filesystem;
using namespace ds::plugin;

static fs::path make_temp(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

static void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (!v || !*v)
        unsetenv(k);
    else
        setenv(k, v, 1);
#endif
}

static void clear_root_state() {
    set_env(kPluginDirEnv, "");
    set_injector_module_dir_for_test(fs::path{});
}

static void test_env_root_wins() {
    auto env_dir = make_temp("ds_plugin_path_env");
    auto mod_root = make_temp("ds_plugin_path_mod");
    fs::create_directories(mod_root / "plugins");

    set_injector_module_dir_for_test(mod_root);
    set_env(kPluginDirEnv, env_dir.string().c_str());

    auto dirs = default_plugin_search_dirs();
    assert(dirs.size() == 1);
    assert(fs::equivalent(dirs.front(), env_dir));

    clear_root_state();
    fs::remove_all(env_dir);
    fs::remove_all(mod_root);
    printf("PASS: env_root_wins\n");
}

static void test_injector_root_without_env() {
    auto mod_root = make_temp("ds_plugin_path_mod_only");
    fs::create_directories(mod_root / "plugins");
    clear_root_state();
    set_injector_module_dir_for_test(mod_root);

    auto dirs = default_plugin_search_dirs();
    assert(dirs.size() == 1);
    assert(fs::equivalent(dirs.front(), mod_root / "plugins"));

    clear_root_state();
    fs::remove_all(mod_root);
    printf("PASS: injector_root_without_env\n");
}

// A broken override is an error, not a hint to scan another install.
static void test_bad_env_does_not_fall_back() {
    auto mod_root = make_temp("ds_plugin_path_bad_env");
    fs::create_directories(mod_root / "plugins");
    clear_root_state();
    set_injector_module_dir_for_test(mod_root);
    set_env(kPluginDirEnv, (mod_root / "missing").string().c_str());

    assert(default_plugin_search_dirs().empty());

    clear_root_state();
    fs::remove_all(mod_root);
    printf("PASS: bad_env_does_not_fall_back\n");
}

static void test_mod_deps_dir_sibling() {
    auto plugins = fs::path("C:/mods/workshop-1/plugins");
    auto mod = mod_root_from_plugins_dir(plugins);
    assert(mod.filename() == "workshop-1" || mod.generic_string().ends_with("workshop-1"));
    auto d = mod_deps_dir(mod);
    assert(d.filename() == "deps");
    assert(d.parent_path() == mod);
    // NOT under plugins/
    assert(d.parent_path().filename() != "plugins");
    // plugins_root/deps layout is wrong for shared runtimes
    assert(d != plugins / "deps");
    printf("PASS: mod_deps_dir_sibling\n");
}

static void test_configure_dll_search_idempotent() {
    reset_plugin_dll_search_for_test();
    assert(plugin_dll_search_roots().empty());
    auto mod = make_temp("ds_plugin_path_deps");
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    fs::create_directories(mod / "deps");
    assert(configure_plugin_dll_search({plugins}));
    // loadlib() walks this list instead of probing the ELF global symbol scope,
    // so it must hold the roots the caller got a module from: <mod>/deps (canonical)
    // and the plugins root itself. plugins/deps does not exist here -> not listed.
    auto roots = plugin_dll_search_roots();
    auto has = [&](const fs::path &p) {
        return std::find(roots.begin(), roots.end(), p) != roots.end();
    };
    assert(has(mod / "deps"));
    assert(has(plugins));
    assert(!has(plugins / "deps"));
    const auto count = roots.size();
    assert(configure_plugin_dll_search({plugins})); // second call OK
    assert(plugin_dll_search_roots().size() == count); // idempotent, no duplicates
    reset_plugin_dll_search_for_test();
    assert(plugin_dll_search_roots().empty());
    printf("PASS: configure_dll_search_idempotent\n");
}

// Stronger deps gate: sibling mod/deps identity + missing-deps is OK + deps never a
// plugin search root. Full LoadLibrary import-from-deps PE probe is residual.
static void test_deps_registration_contract() {
    reset_plugin_dll_search_for_test();
    clear_root_state();

    auto mod = make_temp("ds_mod_root");
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    fs::create_directories(mod / "deps");

    assert(mod_root_from_plugins_dir(plugins) == mod);
    assert(mod_deps_dir(mod) == mod / "deps");
    assert(fs::is_directory(mod / "deps"));
    assert(configure_plugin_dll_search({plugins}));

    // missing deps still OK
    auto mod2 = make_temp("ds_mod_root_nodeps");
    fs::create_directories(mod2 / "plugins");
    assert(configure_plugin_dll_search({mod2 / "plugins"}));

    // bare env override (leaf not "plugins") still uses that dir as mod root
    auto bare = make_temp("ds_plugin_path_bare");
    fs::create_directories(bare / "deps");
    assert(mod_root_from_plugins_dir(bare) == bare);
    assert(mod_deps_dir(bare) == bare / "deps");
    assert(configure_plugin_dll_search({bare}));

    // deps never a plugin search root
    set_env(kPluginDirEnv, plugins.string().c_str());
    auto dirs = default_plugin_search_dirs();
    assert(!dirs.empty());
    for (const auto &d : dirs) {
        assert(d.filename() != "deps");
    }

    set_env(kPluginDirEnv, "");
    reset_plugin_dll_search_for_test();
    printf("PASS: deps_registration_contract\n");
}

static void test_missing_root_does_not_crash() {
    auto dir = make_temp("ds_plugin_path_no_tree"); // no plugins/ child
    clear_root_state();
    set_injector_module_dir_for_test(dir);
    auto dirs = default_plugin_search_dirs();
    assert(dirs.empty());
    clear_root_state();
    fs::remove_all(dir);
    printf("PASS: missing_root_does_not_crash\n");
}

static void test_list_plugin_packages() {
    auto dir = make_temp("ds_plugin_list_pkgs");
    // Lua-face package: plugin_* dir with modinfo.lua.
    fs::create_directories(dir / "plugin_c");
    std::ofstream(dir / "plugin_c" / "modinfo.lua") << "--";
    fs::create_directories(dir / "plugin_a");
    std::ofstream(dir / "plugin_a" / "modinfo.lua") << "--";
    // Native-only package dir (no modinfo.lua) → not a Lua face.
    fs::create_directories(dir / "plugin_b");
    std::ofstream(dir / "plugin_b" / "plugin_b.dll") << "x";
    // Non-plugin dir with a modinfo → ignored.
    fs::create_directories(dir / "not_a_plugin");
    std::ofstream(dir / "not_a_plugin" / "modinfo.lua") << "--";
    // Stray files are not packages.
    std::ofstream(dir / "plugin_flat.dll") << "x";

    auto pkgs = list_plugin_packages(dir.string());
    assert(pkgs.size() == 2);
    assert(pkgs[0] == "plugin_a");
    assert(pkgs[1] == "plugin_c"); // deterministic (sorted)

    assert(list_plugin_packages("").empty());
    assert(list_plugin_packages((dir / "missing").string()).empty());
    fs::remove_all(dir);
    printf("PASS: list_plugin_packages\n");
}

static void test_list_installed_plugin_packages_fallback() {
    auto mod_root = make_temp("ds_plugin_installed_mod");
    fs::create_directories(mod_root / "plugins" / "plugin_fps_render");
    std::ofstream(mod_root / "plugins" / "plugin_fps_render" / "modinfo.lua") << "--";
    clear_root_state();
    set_injector_module_dir_for_test(mod_root);

    // A Workshop item is loaded from Steam UGC while the Lua registry hands over
    // MODROOT-relative paths, so the hint does not resolve on disk; the native
    // search roots must answer instead of a silently empty registry.
    auto pkgs = list_installed_plugin_packages("workshop-3444078585/plugins/");
    assert(pkgs.size() == 1);
    assert(pkgs[0] == "plugin_fps_render");

    // A resolvable hint is used verbatim.
    auto direct = list_installed_plugin_packages((mod_root / "plugins").string());
    assert(direct.size() == 1 && direct[0] == "plugin_fps_render");

    clear_root_state();
    fs::remove_all(mod_root);
    printf("PASS: list_installed_plugin_packages_fallback\n");
}

int main() {
    test_env_root_wins();
    test_injector_root_without_env();
    test_bad_env_does_not_fall_back();
    test_mod_deps_dir_sibling();
    test_configure_dll_search_idempotent();
    test_deps_registration_contract();
    test_missing_root_does_not_crash();
    test_list_plugin_packages();
    test_list_installed_plugin_packages_fallback();
    printf("ALL PASS: plugin_path\n");
    return 0;
}
