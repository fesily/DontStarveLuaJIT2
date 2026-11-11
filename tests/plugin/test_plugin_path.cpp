#include "core/PluginPath.hpp"
#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <doctest/doctest.h>

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

// Restores the process-wide plugin-root state a case mutates: the env override,
// the injector module-dir seam and the DLL search registry. A failed REQUIRE
// unwinds past any tail cleanup, so this runs from the destructor; an entry
// DS_LUAJIT_PLUGIN_DIR value is put back instead of being cleared.
class RootStateGuard {
public:
    RootStateGuard() {
        if (const char *prev = std::getenv(kPluginDirEnv)) {
            has_prev_ = true;
            prev_ = prev;
        }
    }
    ~RootStateGuard() {
        set_env(kPluginDirEnv, has_prev_ ? prev_.c_str() : nullptr);
        set_injector_module_dir_for_test(fs::path{});
        reset_plugin_dll_search_for_test();
    }
    RootStateGuard(const RootStateGuard &) = delete;
    RootStateGuard &operator=(const RootStateGuard &) = delete;

private:
    bool has_prev_ = false;
    std::string prev_;
};

// Removes a case's scratch tree on scope exit (a failing REQUIRE used to skip
// the remove_all at the tail).
class TempDirGuard {
public:
    explicit TempDirGuard(const fs::path &dir) : dir_(dir) {}
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(dir_, ec);
    }
    TempDirGuard(const TempDirGuard &) = delete;
    TempDirGuard &operator=(const TempDirGuard &) = delete;

private:
    fs::path dir_;
};

TEST_CASE("test_plugin_path/env_root_wins") {
    RootStateGuard guard;
    auto env_dir = make_temp("ds_plugin_path_env");
    TempDirGuard env_cleanup(env_dir);
    auto mod_root = make_temp("ds_plugin_path_mod");
    TempDirGuard mod_cleanup(mod_root);
    fs::create_directories(mod_root / "plugins");

    set_injector_module_dir_for_test(mod_root);
    set_env(kPluginDirEnv, env_dir.string().c_str());

    auto dirs = default_plugin_search_dirs();
    REQUIRE_EQ(dirs.size(), 1);
    REQUIRE(fs::equivalent(dirs.front(), env_dir));
}

TEST_CASE("test_plugin_path/injector_root_without_env") {
    RootStateGuard guard;
    auto mod_root = make_temp("ds_plugin_path_mod_only");
    TempDirGuard mod_cleanup(mod_root);
    fs::create_directories(mod_root / "plugins");
    clear_root_state();
    set_injector_module_dir_for_test(mod_root);

    auto dirs = default_plugin_search_dirs();
    REQUIRE_EQ(dirs.size(), 1);
    REQUIRE(fs::equivalent(dirs.front(), mod_root / "plugins"));
}

// A broken override is an error, not a hint to scan another install.
TEST_CASE("test_plugin_path/bad_env_does_not_fall_back") {
    RootStateGuard guard;
    auto mod_root = make_temp("ds_plugin_path_bad_env");
    TempDirGuard mod_cleanup(mod_root);
    fs::create_directories(mod_root / "plugins");
    clear_root_state();
    set_injector_module_dir_for_test(mod_root);
    set_env(kPluginDirEnv, (mod_root / "missing").string().c_str());

    REQUIRE(default_plugin_search_dirs().empty());
}

TEST_CASE("test_plugin_path/mod_deps_dir_sibling") {
    auto plugins = fs::path("C:/mods/workshop-1/plugins");
    auto mod = mod_root_from_plugins_dir(plugins);
    // Platform-shaped leaf check: on Windows filename() is the item dir, elsewhere
    // the whole "C:/mods/..." string arrives as one component.
    REQUIRE((mod.filename() == "workshop-1" || mod.generic_string().ends_with("workshop-1")));
    auto d = mod_deps_dir(mod);
    REQUIRE_EQ(d.filename(), "deps");
    REQUIRE_EQ(d.parent_path(), mod);
    // NOT under plugins/
    REQUIRE_NE(d.parent_path().filename(), "plugins");
    // plugins_root/deps layout is wrong for shared runtimes
    REQUIRE_NE(d, plugins / "deps");
}

TEST_CASE("test_plugin_path/configure_dll_search_idempotent") {
    RootStateGuard guard;
    reset_plugin_dll_search_for_test();
    REQUIRE(plugin_dll_search_roots().empty());
    auto mod = make_temp("ds_plugin_path_deps");
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    fs::create_directories(mod / "deps");
    REQUIRE(configure_plugin_dll_search({plugins}));
    // loadlib() walks this list instead of probing the ELF global symbol scope,
    // so it must hold the roots the caller got a module from: <mod>/deps (canonical)
    // and the plugins root itself. plugins/deps does not exist here -> not listed.
    auto roots = plugin_dll_search_roots();
    auto has = [&](const fs::path &p) {
        return std::find(roots.begin(), roots.end(), p) != roots.end();
    };
    REQUIRE(has(mod / "deps"));
    REQUIRE(has(plugins));
    REQUIRE_FALSE(has(plugins / "deps"));
    const auto count = roots.size();
    REQUIRE(configure_plugin_dll_search({plugins})); // second call OK
    REQUIRE_EQ(plugin_dll_search_roots().size(), count); // idempotent, no duplicates
    reset_plugin_dll_search_for_test();
    REQUIRE(plugin_dll_search_roots().empty());
}

// Stronger deps gate: sibling mod/deps identity + missing-deps is OK + deps never a
// plugin search root. Full LoadLibrary import-from-deps PE probe is residual.
TEST_CASE("test_plugin_path/deps_registration_contract") {
    RootStateGuard guard;
    reset_plugin_dll_search_for_test();
    clear_root_state();

    auto mod = make_temp("ds_mod_root");
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    fs::create_directories(mod / "deps");

    REQUIRE_EQ(mod_root_from_plugins_dir(plugins), mod);
    REQUIRE_EQ(mod_deps_dir(mod), mod / "deps");
    REQUIRE(fs::is_directory(mod / "deps"));
    REQUIRE(configure_plugin_dll_search({plugins}));

    // missing deps still OK
    auto mod2 = make_temp("ds_mod_root_nodeps");
    fs::create_directories(mod2 / "plugins");
    REQUIRE(configure_plugin_dll_search({mod2 / "plugins"}));

    // bare env override (leaf not "plugins") still uses that dir as mod root
    auto bare = make_temp("ds_plugin_path_bare");
    fs::create_directories(bare / "deps");
    REQUIRE_EQ(mod_root_from_plugins_dir(bare), bare);
    REQUIRE_EQ(mod_deps_dir(bare), bare / "deps");
    REQUIRE(configure_plugin_dll_search({bare}));

    // deps never a plugin search root
    set_env(kPluginDirEnv, plugins.string().c_str());
    auto dirs = default_plugin_search_dirs();
    REQUIRE_FALSE(dirs.empty());
    for (const auto &d : dirs) {
        REQUIRE_NE(d.filename(), "deps");
    }
}

TEST_CASE("test_plugin_path/missing_root_does_not_crash") {
    RootStateGuard guard;
    auto dir = make_temp("ds_plugin_path_no_tree"); // no plugins/ child
    TempDirGuard dir_cleanup(dir);
    clear_root_state();
    set_injector_module_dir_for_test(dir);
    auto dirs = default_plugin_search_dirs();
    REQUIRE(dirs.empty());
}

TEST_CASE("test_plugin_path/list_plugin_packages") {
    auto dir = make_temp("ds_plugin_list_pkgs");
    TempDirGuard dir_cleanup(dir);
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
    REQUIRE_EQ(pkgs.size(), 2);
    REQUIRE_EQ(pkgs[0], "plugin_a");
    REQUIRE_EQ(pkgs[1], "plugin_c"); // deterministic (sorted)

    REQUIRE(list_plugin_packages("").empty());
    REQUIRE(list_plugin_packages((dir / "missing").string()).empty());
}

TEST_CASE("test_plugin_path/list_installed_plugin_packages_fallback") {
    RootStateGuard guard;
    auto mod_root = make_temp("ds_plugin_installed_mod");
    TempDirGuard mod_cleanup(mod_root);
    fs::create_directories(mod_root / "plugins" / "plugin_fps_render");
    std::ofstream(mod_root / "plugins" / "plugin_fps_render" / "modinfo.lua") << "--";
    clear_root_state();
    set_injector_module_dir_for_test(mod_root);

    // A Workshop item is loaded from Steam UGC while the Lua registry hands over
    // MODROOT-relative paths, so the hint does not resolve on disk; the native
    // search roots must answer instead of a silently empty registry.
    auto pkgs = list_installed_plugin_packages("workshop-3444078585/plugins/");
    REQUIRE_EQ(pkgs.size(), 1);
    REQUIRE_EQ(pkgs[0], "plugin_fps_render");

    // A resolvable hint is used verbatim.
    auto direct = list_installed_plugin_packages((mod_root / "plugins").string());
    REQUIRE_EQ(direct.size(), 1);
    REQUIRE_EQ(direct[0], "plugin_fps_render");
}
