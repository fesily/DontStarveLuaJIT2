#include "loader/bootstrap/InjectorBootstrap.hpp"
#include "util/PathText.hpp"
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>
#include <doctest/doctest.h>

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

// Restores the env overrides and the resolution seams a case mutates; a failed
// REQUIRE unwinds past the tail cleanup, which would otherwise leak a game root,
// an exe dir or a module override into the next case. Pre-existing
// DS_LUAJIT_INJECTOR(_DIR) values are put back, never cleared.
class BootstrapStateGuard {
public:
    BootstrapStateGuard() {
        capture(kInjectorFileEnv, has_file_, file_);
        capture(kInjectorDirEnv, has_dir_, dir_);
    }
    ~BootstrapStateGuard() {
        set_env(kInjectorFileEnv, has_file_ ? file_.c_str() : nullptr);
        set_env(kInjectorDirEnv, has_dir_ ? dir_.c_str() : nullptr);
        reset_for_test();
    }
    BootstrapStateGuard(const BootstrapStateGuard &) = delete;
    BootstrapStateGuard &operator=(const BootstrapStateGuard &) = delete;

private:
    static void capture(const char *k, bool &has, std::string &value) {
        if (const char *prev = std::getenv(k)) {
            has = true;
            value = prev;
        }
    }
    bool has_file_ = false;
    bool has_dir_ = false;
    std::string file_;
    std::string dir_;
};

// Layout helper: fake game + mod with the real module at the mod root.
static fs::path plant_mod_injector(const fs::path &game_root,
                                   const fs::path &mods_base,
                                   const char *alias) {
    auto mod = mods_base / alias;
    auto module = mod / injector_module_filename();
    touch_file(module);
    touch_file(mod / "modmain.lua");
    return module;
}

TEST_CASE("test_injector_bootstrap/env_file_wins") {
    BootstrapStateGuard guard;
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
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, env_mod));
    REQUIRE_EQ(last_resolve_source_for_test(), "env_file");
    // env success must pin marker
    fs::path marker_val;
    REQUIRE(read_injector_marker(marker_val));
    REQUIRE(fs::equivalent(marker_val, env_mod));
}

// Workshop layout: the item ships "<module>.pkg" only; the shell materializes the
// canonical name while resolving, so the rest of the boot sees the normal layout.
TEST_CASE("test_injector_bootstrap/packaged_twin_materialized_on_resolve") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_pkg_twin");
    auto game = root / "game";
    auto mods = game / "mods";
    auto mod = mods / "workshop-3444078585";
    auto module = mod / injector_module_filename();
    fs::create_directories(mod); // the twin must be creatable before touch_file()
    {
        std::ofstream twin(module.string() + ".pkg", std::ios::binary);
        twin << "ITEM-PAYLOAD";
    }
    touch_file(mod / "modmain.lua");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    REQUIRE_FALSE(fs::exists(module));

    fs::path out;
    REQUIRE(resolve_injector_module(out)); // scan base -> alias -> ".pkg" twin
    REQUIRE(fs::equivalent(out, module));
    REQUIRE_EQ(last_resolve_source_for_test(), "scan");
    REQUIRE(fs::exists(module));
    REQUIRE(fs::exists(fs::path(module.string() + ".pkg"))); // the item copy stays
}

// A replaced "<module>.pkg" must win over the canonical file the previous build left:
// resolution compares the twin and refreshes the derivative, it does not stop at "present".
TEST_CASE("test_injector_bootstrap/packaged_twin_refreshes_stale_canonical_on_resolve") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_pkg_twin_stale");
    auto game = root / "game";
    auto mods = game / "mods";
    auto mod = mods / "workshop-3444078585";
    auto module = mod / injector_module_filename();
    fs::create_directories(mod);
    std::ofstream(module, std::ios::binary) << "OLD-BUILD";
    std::ofstream(module.string() + ".pkg", std::ios::binary) << "NEW-BUILD-REPLACED";
    touch_file(mod / "modmain.lua");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, module));
    {
        std::ifstream in(module, std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(in)),
                                std::istreambuf_iterator<char>());
        REQUIRE_EQ(bytes, "NEW-BUILD-REPLACED");
    }
}

TEST_CASE("test_injector_bootstrap/env_dir_wins_over_marker") {
    BootstrapStateGuard guard;
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
    REQUIRE(write_injector_marker(planted));
    set_env(kInjectorDirEnv, env_dir.string().c_str());

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, env_mod));
    REQUIRE_EQ(last_resolve_source_for_test(), "env_dir");
}

TEST_CASE("test_injector_bootstrap/marker_used_when_no_env") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_marker");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "workshop-3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    REQUIRE(write_injector_marker(planted));

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, planted));
    REQUIRE_EQ(last_resolve_source_for_test(), "marker");
}

TEST_CASE("test_injector_bootstrap/invalid_marker_falls_through_to_scan") {
    BootstrapStateGuard guard;
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
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, planted));
    REQUIRE_EQ(last_resolve_source_for_test(), "scan");
    // successful scan rewrites marker
    fs::path marker_val;
    REQUIRE(read_injector_marker(marker_val));
    REQUIRE(fs::equivalent(marker_val, planted));
}

TEST_CASE("test_injector_bootstrap/scan_alias_workshop") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_scan");
    auto game = root / "game";
    auto mods = game / "mods";
    auto planted = plant_mod_injector(game, mods, "workshop-3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, planted));
    REQUIRE_EQ(last_resolve_source_for_test(), "scan");
}

TEST_CASE("test_injector_bootstrap/ugc_directory_base") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_ugc");
    auto game = root / "game";
    auto ugc_root = root / "custom_workshop";          // -ugc_directory value
    auto ugc_content = ugc_root / "content" / "322330";
    auto planted = plant_mod_injector(game, ugc_content, "3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_cmdline_for_test({"-ugc_directory", ds::util::path_to_utf8(ugc_root)});

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, planted));
    REQUIRE_EQ(last_resolve_source_for_test(), "scan");
}

// Positive control for the derived default: without -ugc_directory the Steam
// layout must still be scanned (the exclusivity test alone would pass if the
// default branch were broken).
TEST_CASE("test_injector_bootstrap/steam_default_base") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_steam_default");
    auto steamapps = root / "steamapps";
    auto game = steamapps / "common" / "game";
    auto default_ugc = steamapps / "workshop" / "content" / "322330";
    auto planted = plant_mod_injector(game, default_ugc, "3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_cmdline_for_test({});

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, planted));
    REQUIRE_EQ(last_resolve_source_for_test(), "scan");
}

// Cmdline tokens are UTF-8; a non-ASCII custom workshop root must resolve.
TEST_CASE("test_injector_bootstrap/ugc_directory_utf8_root") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_ugc_utf8");
    auto game = root / "game";
    // U+1F600 cannot be represented in the ANSI code page, so a narrow
    // fs::path(std::string) misdecodes this UTF-8 token.
    auto ugc_root = root / fs::path(u8"\u81ea\u5b9a\u4e49\u5de5\u574a\U0001F600");
    auto ugc_content = ugc_root / "content" / "322330";
    auto planted = plant_mod_injector(game, ugc_content, "3444078585");

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_cmdline_for_test({"-ugc_directory", ds::util::path_to_utf8(ugc_root)});

    fs::path out;
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, planted));
    REQUIRE_EQ(last_resolve_source_for_test(), "scan");
}

// Custom UGC and the Steam default are mutually exclusive: with
// -ugc_directory present the default steamapps tree must not be scanned.
TEST_CASE("test_injector_bootstrap/ugc_directory_excludes_steam_default") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_ugc_exclusive");
    auto steamapps = root / "steamapps";
    auto game = steamapps / "common" / "game";
    auto default_ugc = steamapps / "workshop" / "content" / "322330";
    auto default_module = plant_mod_injector(game, default_ugc, "3444078585");
    auto custom_root = root / "custom_workshop";
    auto custom_content = custom_root / "content" / "322330";
    fs::create_directories(custom_root);

    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    set_cmdline_for_test({"-ugc_directory", ds::util::path_to_utf8(custom_root)});

    fs::path out;
    REQUIRE_FALSE(resolve_injector_module(out));
    REQUIRE(fs::exists(default_module));

    // The custom tree is the only workshop base, and it wins when populated.
    auto custom_module = plant_mod_injector(game, custom_content, "3444078585");
    REQUIRE(resolve_injector_module(out));
    REQUIRE(fs::equivalent(out, custom_module));
}

TEST_CASE("test_injector_bootstrap/fail_when_nothing") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_none");
    auto game = root / "game";
    fs::create_directories(game / "bin64");
    fs::create_directories(game / "mods");
    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    fs::path out;
    REQUIRE_FALSE(resolve_injector_module(out));
    REQUIRE((last_resolve_source_for_test().empty() ||
             last_resolve_source_for_test() == "none"));
}

TEST_CASE("test_injector_bootstrap/mod_root_from_module_path") {
    auto p = fs::path("C:/mods/luajit") / injector_module_filename();
    auto root = mod_root_from_injector_module(p);
    REQUIRE_EQ(root.filename(), "luajit");
}

TEST_CASE("test_injector_bootstrap/load_fail_fast_no_module") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_load_fail");
    auto game = root / "game";
    fs::create_directories(game / "bin64");
    fs::create_directories(game / "mods");
    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");

    auto fn = load_injector_hook_entry();
    REQUIRE_EQ(fn, nullptr);
}

static std::string read_all(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

TEST_CASE("test_injector_bootstrap/boot_log_written") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_boot_log");
    auto game = root / "game";
    fs::create_directories(game);
    set_marker_game_root_for_test(game);

    REQUIRE_EQ(boot_log_path(), game / "data" / "unsafedata" / kBootLogFileName);
    reset_boot_log();
    append_boot_log("resolve: source=test module=/tmp/x");
    append_boot_log("shell(stub): HookStartupEntry OK");

    const auto text = read_all(boot_log_path());
    REQUIRE_NE(text.find("ds-bootstrap boot log"), std::string::npos);
    REQUIRE_NE(text.find("pid="), std::string::npos);
    REQUIRE_NE(text.find("resolve: source=test module=/tmp/x"), std::string::npos);
    REQUIRE_NE(text.find("shell(stub): HookStartupEntry OK"), std::string::npos);
}

TEST_CASE("test_injector_bootstrap/boot_log_records_failed_resolve") {
    BootstrapStateGuard guard;
    clear_env_and_state();
    auto root = make_temp("ds_inj_boot_log_fail");
    auto game = root / "game";
    fs::create_directories(game / "bin64");
    fs::create_directories(game / "mods");
    set_marker_game_root_for_test(game);
    set_exe_dir_for_test(game / "bin64");
    // Distinct values: the old env_or_null() shared buffer made both lines print
    // the last value, and the raw token line did not exist.
    const auto missing_file = root / "missing" / injector_module_filename();
    const auto missing_dir = root / "missing_dir";
    const auto ugc = root / "ugc";
    set_env(kInjectorFileEnv, missing_file.string().c_str());
    set_env(kInjectorDirEnv, missing_dir.string().c_str());
    set_cmdline_for_test({"-ugc_directory", ds::util::path_to_utf8(ugc)});

    auto fn = load_injector_hook_entry();
    REQUIRE_EQ(fn, nullptr);

    const auto text = read_all(boot_log_path());
    REQUIRE_NE(text.find("ds-bootstrap boot log"), std::string::npos);
    REQUIRE_NE(text.find("resolve: FAILED"), std::string::npos);
    REQUIRE_NE(text.find("DS_LUAJIT_INJECTOR=" + ds::util::path_to_utf8(missing_file)),
               std::string::npos);
    REQUIRE_NE(text.find("DS_LUAJIT_INJECTOR_DIR=" + ds::util::path_to_utf8(missing_dir)),
               std::string::npos);
    REQUIRE_NE(text.find("  -ugc_directory=" + ds::util::path_to_utf8(ugc) +
                         " (workshop root; Steam default NOT scanned)"),
               std::string::npos);
    REQUIRE_NE(text.find("marker: "), std::string::npos);
    REQUIRE_NE(text.find("(missing)"), std::string::npos);
    REQUIRE_NE(text.find("scan bases:"), std::string::npos);
    REQUIRE_EQ(text.find("shell(stub)"), std::string::npos);
}
