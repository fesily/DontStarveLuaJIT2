#include "core/ExternalPluginDiscovery.hpp"
#include "core/PluginHost.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

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

static void test_unmarked_never_loads() {
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
    assert(loads == 0);
    assert(rep.modules_loaded == 0);
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "");
    std::puts("ok unmarked_never_loads");
}

static void test_marked_calls_load_fn() {
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
    assert(rep.mods_accepted == 1);
    assert(rep.modules_loaded == 1);
    assert(loaded.size() == 1);
    assert(loaded[0].find("plugin_x") != std::string::npos);
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "");
    std::puts("ok marked_calls_load_fn");
}

static void test_missing_plugin_id_skips() {
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
    assert(loads == 0);
    assert(rep.mods_accepted == 0);
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "");
    std::puts("ok missing_plugin_id_skips");
}

int main() {
    test_unmarked_never_loads();
    test_marked_calls_load_fn();
    test_missing_plugin_id_skips();
    std::puts("ALL PASS external_discover_gate");
    return 0;
}
