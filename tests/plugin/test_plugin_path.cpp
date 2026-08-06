#include "core/PluginPath.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>

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

static void test_deps_dir_name() {
    auto d = plugins_deps_dir(fs::path("C:/m/plugins"));
    assert(d.filename() == "deps");
    printf("PASS: deps_dir_name\n");
}

static void test_configure_dll_search_idempotent() {
    reset_plugin_dll_search_for_test();
    auto root = make_temp("ds_plugin_path_deps");
    fs::create_directories(root / "deps");
    assert(configure_plugin_dll_search({root}));
    assert(configure_plugin_dll_search({root})); // second call OK
    reset_plugin_dll_search_for_test();
    printf("PASS: configure_dll_search_idempotent\n");
}

int main() {
    test_plugins_dir_from_modmain();
    test_search_order_env_wins();
    test_search_order_mod_without_env();
    test_deps_dir_name();
    test_configure_dll_search_idempotent();
    printf("ALL PASS: plugin_path\n");
    return 0;
}
