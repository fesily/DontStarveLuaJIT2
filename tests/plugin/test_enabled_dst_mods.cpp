#include "core/EnabledDstMods.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>

#if defined(_WIN32)
#  include <Windows.h>
#endif

namespace fs = std::filesystem;
using namespace ds::plugin;

namespace {

fs::path make_temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

void write_file(const fs::path &p, const std::string &body) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << body;
}

void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (v) {
        setenv(k, v, 1);
    } else {
        unsetenv(k);
    }
#endif
}

void test_parse_modoverrides_enabled_only() {
    auto dir = make_temp_dir("ds_enabled_mods_ov");
    auto path = dir / "modoverrides.lua";
    write_file(path, R"lua(
return {
  ["workshop-111"] = { enabled = true, configuration_options = {} },
  ["localmod"] = { enabled = false },
  ["plain"] = { enabled = true },
  ["missing_flag"] = { configuration_options = {} },
}
)lua");
    auto names = parse_modoverrides_enabled_names(path);
    assert(names.size() == 2);
    bool has111 = false, hasplain = false, haslocal = false;
    for (const auto &n : names) {
        if (n == "workshop-111") {
            has111 = true;
        }
        if (n == "plain") {
            hasplain = true;
        }
        if (n == "localmod") {
            haslocal = true;
        }
    }
    assert(has111 && hasplain && !haslocal);
    std::puts("ok parse_modoverrides_enabled_only");
}

void test_parse_missing_file() {
    auto names = parse_modoverrides_enabled_names(
        fs::temp_directory_path() / "ds_enabled_mods_missing" / "nope.lua");
    assert(names.empty());
    std::puts("ok parse_missing_file");
}

void test_resolve_and_enumerate_server() {
    auto sandbox = make_temp_dir("ds_enabled_mods_enum");
    auto mods_root = sandbox / "mods";
    auto mod_a = mods_root / "workshop-111";
    auto mod_b = mods_root / "plain";
    fs::create_directories(mod_a);
    fs::create_directories(mod_b);
    auto ov = sandbox / "modoverrides.lua";
    write_file(ov, R"lua(
return {
  ["workshop-111"] = { enabled = true },
  ["plain"] = { enabled = false },
}
)lua");

    set_env("DS_LUAJIT_MODS_ROOT", mods_root.string().c_str());
    set_env("DS_LUAJIT_MODOVERRIDES_PATH", ov.string().c_str());
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "");
    set_env("DS_LUAJIT_CLIENT_ENABLED_MODS", "");

    auto list = enumerate_enabled_dst_mods(/*is_client=*/false);
    assert(list.size() == 1);
    assert(list[0].name == "workshop-111");
    assert(!list[0].root.empty());
    assert(fs::exists(list[0].root));

    set_env("DS_LUAJIT_MODS_ROOT", "");
    set_env("DS_LUAJIT_MODOVERRIDES_PATH", "");
    std::puts("ok resolve_and_enumerate_server");
}

void test_extra_roots_seam() {
    auto sandbox = make_temp_dir("ds_enabled_mods_extra");
    auto mod = sandbox / "my_pack";
    fs::create_directories(mod);
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", mod.string().c_str());
    set_env("DS_LUAJIT_MODOVERRIDES_PATH", "");
    set_env("DS_LUAJIT_CLIENT_ENABLED_MODS", "");
    auto list = enumerate_enabled_dst_mods(true);
    assert(list.size() == 1);
    assert(list[0].name == "my_pack");
    set_env("DS_LUAJIT_EXTRA_PLUGIN_MOD_ROOTS", "");
    std::puts("ok extra_roots_seam");
}

} // namespace

int main() {
    test_parse_modoverrides_enabled_only();
    test_parse_missing_file();
    test_resolve_and_enumerate_server();
    test_extra_roots_seam();
    std::puts("ALL PASS enabled_dst_mods");
    return 0;
}
