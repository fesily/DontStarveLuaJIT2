#include "plugins/plugin_manager/PluginPinConfig.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <doctest/doctest.h>

using namespace ds::plugin;
namespace fs = std::filesystem;

static fs::path temp_dir(const char *name) {
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

// Restores the config-path override a case mutates; a failed REQUIRE unwinds
// past the tail unset, so the restore runs from the destructor and puts back an
// entry value the user had set instead of clearing it.
class EnvGuard {
public:
    explicit EnvGuard(std::initializer_list<const char *> names) {
        for (const char *n : names) {
            Entry e;
            e.name = n;
            if (const char *prev = std::getenv(n)) {
                e.had = true;
                e.value = prev;
            }
            saved_.push_back(std::move(e));
        }
    }
    ~EnvGuard() {
        for (const auto &e : saved_) {
            set_env(e.name.c_str(), e.had ? e.value.c_str() : nullptr);
        }
    }
    EnvGuard(const EnvGuard &) = delete;
    EnvGuard &operator=(const EnvGuard &) = delete;

private:
    struct Entry {
        std::string name;
        bool had = false;
        std::string value;
    };
    std::vector<Entry> saved_;
};

TEST_CASE("test_plugin_pin_config/defaults") {
    const PluginPinConfig cfg = defaults();
    REQUIRE_EQ(cfg.schema_version, 1);
    REQUIRE_EQ(cfg.repo, "fesily/DontStarveLuaJIT2");
    REQUIRE_EQ(cfg.channel_name, "stable");
    REQUIRE(cfg.release_tag.empty());
    REQUIRE_EQ(cfg.follow_latest, true);
    REQUIRE_EQ(cfg.github_base, "https://github.com");
    REQUIRE_EQ(cfg.gh_proxy_base, "https://gh-proxy.com");
    REQUIRE_EQ(cfg.prefer_proxy, "auto");
    REQUIRE_EQ(cfg.auto_update_on_boot, false); // opt-in only (design default)
    REQUIRE(cfg.pins.empty());
    REQUIRE(cfg.prefer_present.empty());
}

TEST_CASE("test_plugin_pin_config/override_wins_over_channel") {
    PluginPinConfig cfg = defaults();
    cfg.pins["network.rpc"] = PinEntry{"1.2.3", "override"};
    auto ver = desired_version(cfg, "network.rpc", std::optional<std::string>{"9.9.9"});
    REQUIRE(ver.has_value());
    REQUIRE_EQ(*ver, "1.2.3");
}

TEST_CASE("test_plugin_pin_config/channel_when_no_override") {
    PluginPinConfig cfg = defaults();
    // No pin: use channel_version
    auto ver = desired_version(cfg, "core.vm", std::optional<std::string>{"0.2.0"});
    REQUIRE(ver.has_value());
    REQUIRE_EQ(*ver, "0.2.0");

    // Pin with source channel still uses channel_version
    cfg.pins["core.vm"] = PinEntry{"0.1.0", "channel"};
    ver = desired_version(cfg, "core.vm", std::optional<std::string>{"0.3.0"});
    REQUIRE(ver.has_value());
    REQUIRE_EQ(*ver, "0.3.0");

    // Missing channel version => nullopt
    ver = desired_version(cfg, "core.vm", std::nullopt);
    REQUIRE_FALSE(ver.has_value());
}

TEST_CASE("test_plugin_pin_config/missing_file_returns_defaults_ok_false") {
    auto dir = temp_dir("ds_plugin_pin_missing");
    auto path = dir / "does_not_exist.json";
    bool ok = true;
    PluginPinConfig cfg = load_from_file(path, &ok);
    REQUIRE_EQ(ok, false);
    REQUIRE_EQ(cfg.repo, "fesily/DontStarveLuaJIT2");
    REQUIRE_EQ(cfg.channel_name, "stable");
    REQUIRE_EQ(cfg.follow_latest, true);
    REQUIRE(cfg.prefer_present.empty());
    REQUIRE(cfg.pins.empty());
}

TEST_CASE("test_plugin_pin_config/round_trip_save_load") {
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

    REQUIRE(save_to_file(cfg, path));
    REQUIRE(fs::exists(path));

    bool ok = false;
    PluginPinConfig loaded = load_from_file(path, &ok);
    REQUIRE_EQ(ok, true);
    REQUIRE_EQ(loaded.schema_version, 1);
    REQUIRE_EQ(loaded.repo, "fesily/DontStarveLuaJIT2");
    REQUIRE_EQ(loaded.channel_name, "preview");
    REQUIRE_EQ(loaded.release_tag, "v2.9.1");
    REQUIRE_EQ(loaded.follow_latest, false);
    REQUIRE_EQ(loaded.github_base, "https://github.com");
    REQUIRE_EQ(loaded.gh_proxy_base, "https://gh-proxy.com");
    REQUIRE_EQ(loaded.prefer_proxy, "always");
    REQUIRE_EQ(loaded.auto_update_on_boot, true);
    REQUIRE_EQ(loaded.pins.size(), 2);
    REQUIRE_EQ(loaded.pins.at("network.rpc").version, "1.0.0");
    REQUIRE_EQ(loaded.pins.at("network.rpc").source, "override");
    REQUIRE_EQ(loaded.pins.at("core.vm").version, "0.2.0");
    REQUIRE_EQ(loaded.pins.at("core.vm").source, "channel");
    REQUIRE_EQ(loaded.prefer_present.size(), 1);
    REQUIRE_EQ(loaded.prefer_present[0], "core.vm");
}

TEST_CASE("test_plugin_pin_config/prefer_present_defaults_empty") {
    PluginPinConfig cfg = defaults();
    REQUIRE(cfg.prefer_present.empty());

    auto dir = temp_dir("ds_plugin_pin_prefer");
    auto path = dir / "minimal.json";
    {
        std::ofstream out(path);
        out << R"({"schema_version":1})";
    }
    bool ok = false;
    PluginPinConfig loaded = load_from_file(path, &ok);
    REQUIRE_EQ(ok, true);
    REQUIRE(loaded.prefer_present.empty());
}

TEST_CASE("test_plugin_pin_config/resolve_config_path_env_override") {
    EnvGuard env{"DS_LUAJIT_PLUGINS_CONFIG"};
    auto dir = temp_dir("ds_plugin_pin_env");
    auto custom = dir / "custom_plugins.json";
    {
        std::ofstream out(custom);
        out << "{}";
    }
    set_env("DS_LUAJIT_PLUGINS_CONFIG", custom.string().c_str());
    auto resolved = resolve_config_path();
    REQUIRE_EQ(resolved, custom);
    auto def = default_config_path();
    REQUIRE_EQ(def.filename(), "luajit_plugins.json");
    REQUIRE_NE(def.string().find("unsafedata"), std::string::npos);
}
