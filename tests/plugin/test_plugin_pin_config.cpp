#include "plugins/plugin_manager/PluginPinConfig.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include "support/test_assert.hpp"

using namespace ds::plugin;
namespace fs = std::filesystem;

static fs::path temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

static void test_defaults() {
    const PluginPinConfig cfg = defaults();
    DS_REQUIRE(cfg.schema_version == 1);
    DS_REQUIRE(cfg.repo == "fesily/DontStarveLuaJIT2");
    DS_REQUIRE(cfg.channel_name == "stable");
    DS_REQUIRE(cfg.release_tag.empty());
    DS_REQUIRE(cfg.follow_latest == true);
    DS_REQUIRE(cfg.github_base == "https://github.com");
    DS_REQUIRE(cfg.gh_proxy_base == "https://gh-proxy.com");
    DS_REQUIRE(cfg.prefer_proxy == "auto");
    DS_REQUIRE(cfg.auto_update_on_boot == false); // opt-in only (design default)
    DS_REQUIRE(cfg.pins.empty());
    DS_REQUIRE(cfg.prefer_present.empty());
    printf("PASS: defaults\n");
}

static void test_override_wins_over_channel() {
    PluginPinConfig cfg = defaults();
    cfg.pins["network.rpc"] = PinEntry{"1.2.3", "override"};
    auto ver = desired_version(cfg, "network.rpc", std::optional<std::string>{"9.9.9"});
    DS_REQUIRE(ver.has_value());
    DS_REQUIRE(*ver == "1.2.3");
    printf("PASS: override_wins_over_channel\n");
}

static void test_channel_when_no_override() {
    PluginPinConfig cfg = defaults();
    // No pin: use channel_version
    auto ver = desired_version(cfg, "core.vm", std::optional<std::string>{"0.2.0"});
    DS_REQUIRE(ver.has_value());
    DS_REQUIRE(*ver == "0.2.0");

    // Pin with source channel still uses channel_version
    cfg.pins["core.vm"] = PinEntry{"0.1.0", "channel"};
    ver = desired_version(cfg, "core.vm", std::optional<std::string>{"0.3.0"});
    DS_REQUIRE(ver.has_value());
    DS_REQUIRE(*ver == "0.3.0");

    // Missing channel version => nullopt
    ver = desired_version(cfg, "core.vm", std::nullopt);
    DS_REQUIRE(!ver.has_value());
    printf("PASS: channel_when_no_override\n");
}

static void test_missing_file_returns_defaults_ok_false() {
    auto dir = temp_dir("ds_plugin_pin_missing");
    auto path = dir / "does_not_exist.json";
    bool ok = true;
    PluginPinConfig cfg = load_from_file(path, &ok);
    DS_REQUIRE(ok == false);
    DS_REQUIRE(cfg.repo == "fesily/DontStarveLuaJIT2");
    DS_REQUIRE(cfg.channel_name == "stable");
    DS_REQUIRE(cfg.follow_latest == true);
    DS_REQUIRE(cfg.prefer_present.empty());
    DS_REQUIRE(cfg.pins.empty());
    printf("PASS: missing_file_returns_defaults_ok_false\n");
}

static void test_round_trip_save_load() {
    auto dir = temp_dir("ds_plugin_pin_roundtrip");
    auto path = dir / "luajit_plugins.json";

    PluginPinConfig cfg = defaults();
    cfg.schema_version = 1;
    cfg.repo = "fesily/DontStarveLuaJIT2";
    cfg.channel_name = "preview";
    cfg.release_tag = "v2.9.1";
    cfg.follow_latest = false;
    cfg.github_base = "https://github.com";
    cfg.gh_proxy_base = "https://gh-proxy.com";
    cfg.prefer_proxy = "always";
    cfg.auto_update_on_boot = true;
    cfg.pins["network.rpc"] = PinEntry{"1.0.0", "override"};
    cfg.pins["core.vm"] = PinEntry{"0.2.0", "channel"};
    cfg.prefer_present = {"core.vm"};

    DS_REQUIRE(save_to_file(cfg, path));
    DS_REQUIRE(fs::exists(path));

    bool ok = false;
    PluginPinConfig loaded = load_from_file(path, &ok);
    DS_REQUIRE(ok == true);
    DS_REQUIRE(loaded.schema_version == 1);
    DS_REQUIRE(loaded.repo == "fesily/DontStarveLuaJIT2");
    DS_REQUIRE(loaded.channel_name == "preview");
    DS_REQUIRE(loaded.release_tag == "v2.9.1");
    DS_REQUIRE(loaded.follow_latest == false);
    DS_REQUIRE(loaded.github_base == "https://github.com");
    DS_REQUIRE(loaded.gh_proxy_base == "https://gh-proxy.com");
    DS_REQUIRE(loaded.prefer_proxy == "always");
    DS_REQUIRE(loaded.auto_update_on_boot == true);
    DS_REQUIRE(loaded.pins.size() == 2);
    DS_REQUIRE(loaded.pins.at("network.rpc").version == "1.0.0");
    DS_REQUIRE(loaded.pins.at("network.rpc").source == "override");
    DS_REQUIRE(loaded.pins.at("core.vm").version == "0.2.0");
    DS_REQUIRE(loaded.pins.at("core.vm").source == "channel");
    DS_REQUIRE(loaded.prefer_present.size() == 1);
    DS_REQUIRE(loaded.prefer_present[0] == "core.vm");
    printf("PASS: round_trip_save_load\n");
}

static void test_prefer_present_defaults_empty() {
    PluginPinConfig cfg = defaults();
    DS_REQUIRE(cfg.prefer_present.empty());

    auto dir = temp_dir("ds_plugin_pin_prefer");
    auto path = dir / "minimal.json";
    {
        std::ofstream out(path);
        out << R"({"schema_version":1})";
    }
    bool ok = false;
    PluginPinConfig loaded = load_from_file(path, &ok);
    DS_REQUIRE(ok == true);
    DS_REQUIRE(loaded.prefer_present.empty());
    printf("PASS: prefer_present_defaults_empty\n");
}

static void test_resolve_config_path_env_override() {
    auto dir = temp_dir("ds_plugin_pin_env");
    auto custom = dir / "custom_plugins.json";
    {
        std::ofstream out(custom);
        out << "{}";
    }
#if defined(_WIN32)
    _putenv_s("DS_LUAJIT_PLUGINS_CONFIG", custom.string().c_str());
#else
    setenv("DS_LUAJIT_PLUGINS_CONFIG", custom.string().c_str(), 1);
#endif
    auto resolved = resolve_config_path();
    DS_REQUIRE(resolved == custom);
#if defined(_WIN32)
    _putenv_s("DS_LUAJIT_PLUGINS_CONFIG", "");
#else
    unsetenv("DS_LUAJIT_PLUGINS_CONFIG");
#endif
    auto def = default_config_path();
    DS_REQUIRE(def.filename() == "luajit_plugins.json");
    DS_REQUIRE(def.string().find("unsafedata") != std::string::npos);
    printf("PASS: resolve_config_path_env_override\n");
}

int main() {
    test_defaults();
    test_override_wins_over_channel();
    test_channel_when_no_override();
    test_missing_file_returns_defaults_ok_false();
    test_round_trip_save_load();
    test_prefer_present_defaults_empty();
    test_resolve_config_path_env_override();
    printf("ALL PASS plugin_pin_config\n");
    return 0;
}
