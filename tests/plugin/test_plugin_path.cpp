#include "core/PluginPath.hpp"
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

static void test_plugins_dir_from_modmain() {
    auto p = plugins_dir_from_modmain("C:/mods/workshop-1/modmain.lua");
    assert(p.filename() == "plugins");
    assert(p.parent_path().filename() == "workshop-1" ||
           p.parent_path().generic_string().ends_with("workshop-1"));
    assert(plugins_dir_from_modmain("").empty());
    printf("PASS: plugins_dir_from_modmain\n");
}

static void test_search_order_env_wins() {
    auto env_dir = make_temp("ds_plugin_path_env");
    auto mod_root = make_temp("ds_plugin_path_mod");
    fs::create_directories(mod_root / "plugins");
    auto modmain = (mod_root / "modmain.lua").string();
    std::ofstream(mod_root / "modmain.lua") << "--";

    set_modmain_path_override_for_test(modmain); // implement in PluginPath
    set_env(kPluginDirEnv, env_dir.string().c_str());

    auto dirs = default_plugin_search_dirs();
    assert(!dirs.empty());
    // env first
    assert(fs::equivalent(dirs.front(), env_dir));
    // mod plugins present later if distinct
    bool saw_mod = false;
    for (size_t i = 1; i < dirs.size(); ++i) {
        if (fs::equivalent(dirs[i], mod_root / "plugins"))
            saw_mod = true;
    }
    assert(saw_mod);

    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test("");
    printf("PASS: search_order_env_wins\n");
}

static void test_search_order_mod_without_env() {
    auto mod_root = make_temp("ds_plugin_path_mod_only");
    fs::create_directories(mod_root / "plugins");
    auto modmain = (mod_root / "modmain.lua").string();
    std::ofstream(mod_root / "modmain.lua") << "--";
    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test(modmain);

    auto dirs = default_plugin_search_dirs();
    assert(!dirs.empty());
    assert(fs::equivalent(dirs.front(), mod_root / "plugins"));

    set_modmain_path_override_for_test("");
    printf("PASS: search_order_mod_without_env\n");
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
    auto mod = make_temp("ds_plugin_path_deps");
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    fs::create_directories(mod / "deps");
    assert(configure_plugin_dll_search({plugins}));
    assert(configure_plugin_dll_search({plugins})); // second call OK
    reset_plugin_dll_search_for_test();
    printf("PASS: configure_dll_search_idempotent\n");
}

// Stronger deps gate: sibling mod/deps identity + missing-deps is OK + deps never a
// plugin search root. Full LoadLibrary import-from-deps PE probe is residual.
static void test_deps_registration_contract() {
    reset_plugin_dll_search_for_test();
    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test("");

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

static void test_empty_modmain_does_not_crash() {
    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test("");
    // May discover real game install or only injector fallback; must not throw.
    auto dirs = default_plugin_search_dirs();
    (void)dirs;
    printf("PASS: empty_modmain_does_not_crash (dirs=%zu)\n", dirs.size());
}

int main() {
    test_plugins_dir_from_modmain();
    test_search_order_env_wins();
    test_search_order_mod_without_env();
    test_mod_deps_dir_sibling();
    test_configure_dll_search_idempotent();
    test_deps_registration_contract();
    test_empty_modmain_does_not_crash();
    printf("ALL PASS: plugin_path\n");
    return 0;
}
