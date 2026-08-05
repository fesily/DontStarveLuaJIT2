#include "plugins/plugin_manager/PluginPinConfig.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

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
    assert(cfg.schema_version == 1);
    assert(cfg.repo == "fesily/DontStarveLuaJIT2");
    assert(cfg.channel_name == "stable");
    assert(cfg.release_tag.empty());
    assert(cfg.follow_latest == true);
    assert(cfg.github_base == "https://github.com");
    assert(cfg.gh_proxy_base == "https://gh-proxy.com");
    assert(cfg.prefer_proxy == "auto");
    assert(cfg.auto_apply_on_boot == false);
    assert(cfg.pins.empty());
    assert(cfg.prefer_present.empty());
    printf("PASS: defaults\n");
}

static void test_override_wins_over_channel() {
    PluginPinConfig cfg = defaults();
    cfg.pins["network.rpc"] = PinEntry{"1.2.3", "override"};
    auto ver = desired_version(cfg, "network.rpc", std::optional<std::string>{"9.9.9"});
    assert(ver.has_value());
    assert(*ver == "1.2.3");
    printf("PASS: override_wins_over_channel\n");
}

static void test_channel_when_no_override() {
    PluginPinConfig cfg = defaults();
    // No pin: use channel_version
    auto ver = desired_version(cfg, "core.vm", std::optional<std::string>{"0.2.0"});
    assert(ver.has_value());
    assert(*ver == "0.2.0");

    // Pin with source channel still uses channel_version
    cfg.pins["core.vm"] = PinEntry{"0.1.0", "channel"};
    ver = desired_version(cfg, "core.vm", std::optional<std::string>{"0.3.0"});
    assert(ver.has_value());
    assert(*ver == "0.3.0");

    // Missing channel version => nullopt
    ver = desired_version(cfg, "core.vm", std::nullopt);
    assert(!ver.has_value());
    printf("PASS: channel_when_no_override\n");
}

static void test_missing_file_returns_defaults_ok_false() {
    auto dir = temp_dir("ds_plugin_pin_missing");
    auto path = dir / "does_not_exist.json";
    bool ok = true;
    PluginPinConfig cfg = load_from_file(path, &ok);
    assert(ok == false);
    assert(cfg.repo == "fesily/DontStarveLuaJIT2");
    assert(cfg.channel_name == "stable");
    assert(cfg.follow_latest == true);
    assert(cfg.prefer_present.empty());
    assert(cfg.pins.empty());
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
    cfg.auto_apply_on_boot = true;
    cfg.pins["network.rpc"] = PinEntry{"1.0.0", "override"};
    cfg.pins["core.vm"] = PinEntry{"0.2.0", "channel"};
    cfg.prefer_present = {"core.vm"};

    assert(save_to_file(cfg, path));
    assert(fs::exists(path));

    bool ok = false;
    PluginPinConfig loaded = load_from_file(path, &ok);
    assert(ok == true);
    assert(loaded.schema_version == 1);
    assert(loaded.repo == "fesily/DontStarveLuaJIT2");
    assert(loaded.channel_name == "preview");
    assert(loaded.release_tag == "v2.9.1");
    assert(loaded.follow_latest == false);
    assert(loaded.github_base == "https://github.com");
    assert(loaded.gh_proxy_base == "https://gh-proxy.com");
    assert(loaded.prefer_proxy == "always");
    assert(loaded.auto_apply_on_boot == true);
    assert(loaded.pins.size() == 2);
    assert(loaded.pins.at("network.rpc").version == "1.0.0");
    assert(loaded.pins.at("network.rpc").source == "override");
    assert(loaded.pins.at("core.vm").version == "0.2.0");
    assert(loaded.pins.at("core.vm").source == "channel");
    assert(loaded.prefer_present.size() == 1);
    assert(loaded.prefer_present[0] == "core.vm");
    printf("PASS: round_trip_save_load\n");
}

static void test_prefer_present_defaults_empty() {
    PluginPinConfig cfg = defaults();
    assert(cfg.prefer_present.empty());

    auto dir = temp_dir("ds_plugin_pin_prefer");
    auto path = dir / "minimal.json";
    {
        std::ofstream out(path);
        out << R"({"schema_version":1})";
    }
    bool ok = false;
    PluginPinConfig loaded = load_from_file(path, &ok);
    assert(ok == true);
    assert(loaded.prefer_present.empty());
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
    assert(resolved == custom);
#if defined(_WIN32)
    _putenv_s("DS_LUAJIT_PLUGINS_CONFIG", "");
#else
    unsetenv("DS_LUAJIT_PLUGINS_CONFIG");
#endif
    auto def = default_config_path();
    assert(def.filename() == "luajit_plugins.json");
    assert(def.string().find("unsafedata") != std::string::npos);
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
