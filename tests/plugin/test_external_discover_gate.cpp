#include "core/ExternalPluginDiscovery.hpp"
#include "core/PluginHost.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>
#include <doctest/doctest.h>

#if defined(_WIN32)
#  include <Windows.h>
#endif

namespace fs = std::filesystem;
using namespace ds::plugin;

static void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (v) setenv(k, v, 1); else unsetenv(k);
#endif
}

static fs::path make_temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

static void write_file(const fs::path &p, const std::string &body) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << body;
}

// Restores the discovery env this case mutates; a failed REQUIRE unwinds past
// the tail set_env("", ...) calls, so the restore runs from the destructor. An
// entry value is put back verbatim instead of being blanket-cleared.
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

TEST_CASE("test_external_discover_gate/unmarked_never_loads") {
    EnvGuard env{"DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "DS_LUAJIT_MODOVERRIDES_PATH",
                "DS_LUAJIT_CLIENT_ENABLED_MODS"};
    auto sandbox = make_temp_dir("ds_ext_gate_unmarked");
    auto mod = sandbox / "evil_mod";
    write_file(mod / "modinfo.lua", "name='x'\n");
#if defined(_WIN32)
    write_file(mod / "plugins" / "plugin_x" / "plugin_x.dll", "not a dll");
#else
    write_file(mod / "plugins" / "plugin_x" / "plugin_x.so", "not a so");
#endif
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", mod.string().c_str());
    set_env("DS_LUAJIT_MODOVERRIDES_PATH", "");
    set_env("DS_LUAJIT_CLIENT_ENABLED_MODS", "");
    int loads = 0;
    PluginHost host;
    auto rep = discover_and_load_external_plugins(
        host, true, {},
        [&](const fs::path &, std::string *) {
            ++loads;
            return true;
        });
    REQUIRE_EQ(loads, 0);
    REQUIRE_EQ(rep.modules_loaded, 0);
}

TEST_CASE("test_external_discover_gate/marked_calls_load_fn") {
    EnvGuard env{"DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "DS_LUAJIT_MODOVERRIDES_PATH",
                "DS_LUAJIT_CLIENT_ENABLED_MODS"};
    auto sandbox = make_temp_dir("ds_ext_gate_marked");
    auto mod = sandbox / "good_mod";
    write_file(mod / "modinfo.lua",
               "luajit_plugin_pack = true\nplugin_id = \"vendor.x\"\nname='g'\n");
#if defined(_WIN32)
    auto dll = mod / "plugins" / "plugin_x" / "plugin_x.dll";
#else
    auto dll = mod / "plugins" / "plugin_x" / "plugin_x.so";
#endif
    write_file(dll, "x");
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", mod.string().c_str());
    std::vector<std::string> loaded;
    PluginHost host;
    auto rep = discover_and_load_external_plugins(
        host, true, {},
        [&](const fs::path &p, std::string *) {
            loaded.push_back(p.filename().string());
            return true;
        });
    REQUIRE_EQ(rep.mods_accepted, 1);
    REQUIRE_EQ(rep.modules_loaded, 1);
    REQUIRE_EQ(loaded.size(), 1);
    REQUIRE_NE(loaded[0].find("plugin_x"), std::string::npos);
}

TEST_CASE("test_external_discover_gate/missing_plugin_id_skips") {
    EnvGuard env{"DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "DS_LUAJIT_MODOVERRIDES_PATH",
                "DS_LUAJIT_CLIENT_ENABLED_MODS"};
    auto sandbox = make_temp_dir("ds_ext_gate_noid");
    auto mod = sandbox / "noid_mod";
    write_file(mod / "modinfo.lua", "luajit_plugin_pack = true\nname='n'\n");
#if defined(_WIN32)
    write_file(mod / "plugins" / "plugin_x" / "plugin_x.dll", "x");
#else
    write_file(mod / "plugins" / "plugin_x" / "plugin_x.so", "x");
#endif
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", mod.string().c_str());
    int loads = 0;
    PluginHost host;
    auto rep = discover_and_load_external_plugins(
        host, true, {},
        [&](const fs::path &, std::string *) {
            ++loads;
            return true;
        });
    REQUIRE_EQ(loads, 0);
    REQUIRE_EQ(rep.mods_accepted, 0);
}
