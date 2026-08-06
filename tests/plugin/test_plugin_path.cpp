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

// Stronger deps gate: deps path identity + missing-deps is OK + deps never a
// plugin search root. Full LoadLibrary import-from-deps PE probe is residual.
static void test_deps_registration_contract() {
    reset_plugin_dll_search_for_test();
    set_env(kPluginDirEnv, "");
    set_modmain_path_override_for_test("");

    auto root_with_deps = make_temp("ds_plugin_path_deps_ok");
    auto root_no_deps = make_temp("ds_plugin_path_deps_missing");
    fs::create_directories(root_with_deps / "deps");
    // root_no_deps intentionally has no deps/ subdirectory.

    const auto deps = plugins_deps_dir(root_with_deps);
    assert(deps == root_with_deps / "deps");
    assert(fs::is_directory(deps));
    assert(deps.filename() == "deps");
    // Naming contract: deps is sibling under plugins root, not a search root itself.
    assert(plugins_deps_dir(root_no_deps) == root_no_deps / "deps");
    assert(!fs::exists(plugins_deps_dir(root_no_deps)));

    // configure must succeed with and without deps present.
    assert(configure_plugin_dll_search({root_with_deps}));
    assert(configure_plugin_dll_search({root_no_deps}));
    assert(configure_plugin_dll_search({root_with_deps, root_no_deps}));

    // Search dirs must never return the deps path as a plugin root.
    set_env(kPluginDirEnv, root_with_deps.string().c_str());
    auto dirs = default_plugin_search_dirs();
    assert(!dirs.empty());
    for (const auto &d : dirs) {
        assert(d.filename() != "deps");
        // deps itself must not be listed even if someone points env at plugins/
        assert(!fs::equivalent(d, deps));
        // If env points at plugins root, that root is listed — but not its deps child
        // as a separate entry from this API.
        if (fs::equivalent(d, root_with_deps)) {
            // ok: plugins root is a search root
        }
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
    test_deps_dir_name();
    test_configure_dll_search_idempotent();
    test_deps_registration_contract();
    test_empty_modmain_does_not_crash();
    printf("ALL PASS: plugin_path\n");
    return 0;
}
