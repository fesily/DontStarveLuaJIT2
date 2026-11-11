#include "core/PluginPath.hpp"
#include "util/PathText.hpp"
#include <algorithm>
#include <cstdlib>
#include <cstring>
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

#if defined(_WIN32)
static std::wstring wide_key(const char *k) {
    return std::wstring(k, k + std::strlen(k));
}
#endif

// The production reader uses the wide environment on Windows, so tests that
// carry non-ASCII paths must set it the same way (path::string() would narrow
// through the ANSI code page and could not catch a misdecoded value).
static void set_env_path(const char *k, const fs::path &value) {
#if defined(_WIN32)
    _wputenv_s(wide_key(k).c_str(), value.wstring().c_str());
#else
    setenv(k, value.c_str(), 1);
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
#if defined(_WIN32)
        if (const wchar_t *prev = _wgetenv(wide_key(kPluginDirEnv).c_str());
            prev != nullptr && prev[0] != L'\0') {
            has_prev_ = true;
            prev_ = prev;
        }
#else
        if (const char *prev = std::getenv(kPluginDirEnv); prev != nullptr) {
            has_prev_ = true;
            prev_ = prev;
        }
#endif
    }
    ~RootStateGuard() {
#if defined(_WIN32)
        _wputenv_s(wide_key(kPluginDirEnv).c_str(), has_prev_ ? prev_.c_str() : L"");
#else
        set_env(kPluginDirEnv, has_prev_ ? prev_.c_str() : nullptr);
#endif
        set_injector_module_dir_for_test(fs::path{});
        reset_plugin_dll_search_for_test();
    }
    RootStateGuard(const RootStateGuard &) = delete;
    RootStateGuard &operator=(const RootStateGuard &) = delete;

private:
    bool has_prev_ = false;
#if defined(_WIN32)
    std::wstring prev_;
#else
    std::string prev_;
#endif
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
    set_env_path(kPluginDirEnv, env_dir);

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
    set_env_path(kPluginDirEnv, mod_root / "missing");

    REQUIRE(default_plugin_search_dirs().empty());
}

TEST_CASE("test_plugin_path/env_root_is_utf8") {
    RootStateGuard guard;
    auto base = make_temp("ds_plugin_path_utf8");
    TempDirGuard cleanup(base);
    // U+1F600 is not representable in the ANSI code page: the narrow getenv()
    // path turns it into '?' and cannot find the directory.
    auto env_dir = base / fs::path(u8"\u63d2\u4ef6\u76ee\u5f55\U0001F600");
    std::error_code ec;
    fs::create_directories(env_dir, ec);
    REQUIRE_FALSE(ec);
    set_injector_module_dir_for_test(fs::path{});
    set_env_path(kPluginDirEnv, env_dir);

    auto dirs = default_plugin_search_dirs();
    REQUIRE_EQ(dirs.size(), 1);
    REQUIRE(fs::equivalent(dirs.front(), env_dir));
}

// A broken override must not silently re-root to the injector tree.
TEST_CASE("test_plugin_path/env_root_must_be_directory") {
    RootStateGuard guard;
    auto base = make_temp("ds_plugin_path_file_env");
    TempDirGuard cleanup(base);
    auto file = base / "not_a_dir";
    std::ofstream(file) << "x";
    // A module-relative fallback (the removed PluginLocalInventory path) would
    // find this plugins/ dir; the root resolver itself must still return empty.
    fs::create_directories(base / "plugins");
    set_injector_module_dir_for_test(base);
    set_env_path(kPluginDirEnv, file);

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
    set_env_path(kPluginDirEnv, plugins);
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

    auto pkgs = list_plugin_packages(ds::util::path_to_utf8(dir));
    REQUIRE_EQ(pkgs.size(), 2);
    REQUIRE_EQ(pkgs[0], "plugin_a");
    REQUIRE_EQ(pkgs[1], "plugin_c"); // deterministic (sorted)

    REQUIRE(list_plugin_packages("").empty());
    REQUIRE(list_plugin_packages(ds::util::path_to_utf8(dir / "missing")).empty());
}

TEST_CASE("test_plugin_path/list_packages_utf8_roundtrip") {
    auto dir = make_temp("ds_plugin_list_utf8");
    TempDirGuard cleanup(dir);
    auto package = dir / fs::path(u8"plugin_\u6d4b\u8bd5");
    fs::create_directories(package);
    std::ofstream(package / "modinfo.lua") << "--";

    auto pkgs = list_plugin_packages(ds::util::path_to_utf8(dir));
    REQUIRE_EQ(pkgs.size(), 1);
    REQUIRE_EQ(pkgs[0], ds::util::path_to_utf8(package.filename()));
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
    // root must answer instead of a silently empty registry.
    auto pkgs = list_installed_plugin_packages("workshop-3444078585/plugins/");
    REQUIRE_EQ(pkgs.size(), 1);
    REQUIRE_EQ(pkgs[0], "plugin_fps_render");
}

// The native root is the source of truth: a resolvable MODROOT hint naming a
// different tree must not win.
TEST_CASE("test_plugin_path/installed_packages_prefer_native_root") {
    RootStateGuard guard;
    auto native = make_temp("ds_plugin_native_root");
    TempDirGuard native_cleanup(native);
    auto hint = make_temp("ds_plugin_hint_root");
    TempDirGuard hint_cleanup(hint);
    fs::create_directories(native / "plugins" / "plugin_native_only");
    std::ofstream(native / "plugins" / "plugin_native_only" / "modinfo.lua") << "--";
    fs::create_directories(hint / "plugins" / "plugin_hint_only");
    std::ofstream(hint / "plugins" / "plugin_hint_only" / "modinfo.lua") << "--";
    clear_root_state();
    set_injector_module_dir_for_test(native);

    auto pkgs = list_installed_plugin_packages(ds::util::path_to_utf8(hint / "plugins"));
    REQUIRE_EQ(pkgs.size(), 1);
    REQUIRE_EQ(pkgs[0], "plugin_native_only");
}

// Without a native root the engine-relative hint is still usable.
TEST_CASE("test_plugin_path/installed_packages_use_hint_without_root") {
    RootStateGuard guard;
    auto native = make_temp("ds_plugin_no_root");
    TempDirGuard native_cleanup(native);
    auto hint = make_temp("ds_plugin_hint_only");
    TempDirGuard hint_cleanup(hint);
    fs::create_directories(hint / "plugins" / "plugin_hint_only");
    std::ofstream(hint / "plugins" / "plugin_hint_only" / "modinfo.lua") << "--";
    clear_root_state();
    set_injector_module_dir_for_test(native); // no plugins/ child

    auto pkgs = list_installed_plugin_packages(ds::util::path_to_utf8(hint / "plugins"));
    REQUIRE_EQ(pkgs.size(), 1);
    REQUIRE_EQ(pkgs[0], "plugin_hint_only");
}
