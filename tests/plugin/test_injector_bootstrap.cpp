#include "loader/bootstrap/InjectorBootstrap.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;
using namespace ds::bootstrap;

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
    if (!v || !*v) unsetenv(k);
    else setenv(k, v, 1);
#endif
}

static void touch_file(const fs::path &p) {
    fs::create_directories(p.parent_path());
    std::ofstream(p) << "x";
}

static void clear_env_and_state() {
    set_env(kInjectorFileEnv, "");
    set_env(kInjectorDirEnv, "");
    reset_for_test();
}

// Layout helper: fake game + mod with real module under mod/bin64/<name>
static fs::path plant_mod_injector(const fs::path &game_root,
                                   const fs::path &mods_base,
                                   const char *alias) {
    auto mod = mods_base / alias;
    auto module = mod / "bin64" / injector_module_filename();
    touch_file(module);
    touch_file(mod / "modmain.lua");
    return module;
}

static void test_env_file_wins() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_env_file");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "luajit");
    auto env_mod = root / "from_env" / injector_module_filename();
    touch_file(env_mod);

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_env(kInjectorFileEnv, env_mod.string().c_str());

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, env_mod));
    assert(last_resolve_source_for_test() == "env_file");
    // env success must pin marker
    fs::path marker_val;
    assert(read_injector_marker(marker_val));
    assert(fs::equivalent(marker_val, env_mod));

    clear_env_and_state();
    printf("PASS: env_file_wins\n");
}

static void test_env_dir_wins_over_marker() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_env_dir");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "luajit");
    auto env_dir = root / "envdir";
    auto env_mod = env_dir / injector_module_filename();
    touch_file(env_mod);

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    // stale marker points at planted
    assert(write_injector_marker(planted));
    set_env(kInjectorDirEnv, env_dir.string().c_str());

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, env_mod));
    assert(last_resolve_source_for_test() == "env_dir");

    clear_env_and_state();
    printf("PASS: env_dir_wins_over_marker\n");
}

static void test_marker_used_when_no_env() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_marker");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "workshop-3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    assert(write_injector_marker(planted));

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "marker");

    clear_env_and_state();
    printf("PASS: marker_used_when_no_env\n");
}

static void test_invalid_marker_falls_through_to_scan() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_bad_marker");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "luajit2");
    auto missing = root / "gone" / injector_module_filename();
    // write marker to missing path without creating file
    fs::create_directories(game / "data" / "unsafedata");
    std::ofstream(game / "data" / "unsafedata" / kMarkerFileName)
        << missing.string() << "\n";

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "scan");
    // successful scan rewrites marker
    fs::path marker_val;
    assert(read_injector_marker(marker_val));
    assert(fs::equivalent(marker_val, planted));

    clear_env_and_state();
    printf("PASS: invalid_marker_falls_through_to_scan\n");
}

static void test_scan_alias_workshop() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_scan");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "workshop-3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "scan");

    clear_env_and_state();
    printf("PASS: scan_alias_workshop\n");
}

static void test_ugc_directory_base() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_ugc");
    auto game = root / "game";
    auto ugc = root / "ugc_content";
    auto planted = plant_mod_injector(game, ugc, "3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_cmdline_for_test({"-ugc_directory", ugc.string()});

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, planted));
    assert(last_resolve_source_for_test() == "scan");

    clear_env_and_state();
    printf("PASS: ugc_directory_base\n");
}

static void test_legacy_no_marker_write() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_legacy");
    auto game = root / "game";
    auto exe_dir = game / "bin64";
    auto legacy = exe_dir / injector_module_filename();
    touch_file(legacy);
    // ensure no mod injectors
    fs::create_directories(game / "mods");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(exe_dir);

    fs::path out;
    assert(resolve_injector_module(out));
    assert(fs::equivalent(out, legacy));
    assert(last_resolve_source_for_test() == "legacy");
    fs::path marker_val;
    assert(!read_injector_marker(marker_val)); // must NOT pin legacy

    clear_env_and_state();
    printf("PASS: legacy_no_marker_write\n");
}

static void test_fail_when_nothing() {
    clear_env_and_state();
    auto root = make_temp("ds_inj_none");
    auto game = root / "game";
    fs::create_directories(game / "bin64");
    fs::create_directories(game / "mods");
    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    assert(!resolve_injector_module(out));
    assert(last_resolve_source_for_test().empty() ||
           last_resolve_source_for_test() == "none");

    clear_env_and_state();
    printf("PASS: fail_when_nothing\n");
}

int main() {
    test_env_file_wins();
    test_env_dir_wins_over_marker();
    test_marker_used_when_no_env();
    test_invalid_marker_falls_through_to_scan();
    test_scan_alias_workshop();
    test_ugc_directory_base();
    test_legacy_no_marker_write();
    test_fail_when_nothing();
    printf("ALL PASS test_injector_bootstrap (task1)\n");
    return 0;
}
