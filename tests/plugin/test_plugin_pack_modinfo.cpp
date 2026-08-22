#include "core/PluginPackModinfo.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

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

fs::path write_modinfo(const fs::path &mod_root, const std::string &body) {
    fs::create_directories(mod_root);
    auto p = mod_root / "modinfo.lua";
    std::ofstream out(p, std::ios::binary);
    out << body;
    out.close();
    assert(out.good() || fs::exists(p));
    return p;
}

void test_missing_file() {
    auto missing = fs::temp_directory_path() / "ds_plugin_pack_modinfo_missing" / "modinfo.lua";
    std::error_code ec;
    fs::remove_all(missing.parent_path(), ec);
    auto info = parse_plugin_pack_modinfo(missing);
    assert(!info.ok);
    assert(!info.luajit_plugin_pack);
    assert(info.plugin_id.empty());
    assert(info.parse_error == "open_failed");
    assert(!external_pack_trust_ok(info));
    std::puts("ok missing_file");
}

void test_no_pack_marker() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_nopack");
    auto path = write_modinfo(root, R"lua(
name = "Plain Mod"
description = "no pack marker"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(info.ok);
    assert(!info.luajit_plugin_pack);
    assert(info.plugin_id.empty());
    assert(info.parse_error.empty());
    assert(!external_pack_trust_ok(info));
    std::puts("ok no_pack_marker");
}

void test_pack_without_plugin_id() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_noid");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
name = "Pack Missing Id"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(info.ok);
    assert(info.luajit_plugin_pack);
    assert(info.plugin_id.empty());
    assert(!external_pack_trust_ok(info));
    std::puts("ok pack_without_plugin_id");
}

void test_pack_with_plugin_id() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_ok");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = "vendor.x"
name = "Trusted Pack"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(info.ok);
    assert(info.luajit_plugin_pack);
    assert(info.plugin_id == "vendor.x");
    assert(info.parse_error.empty());
    assert(external_pack_trust_ok(info));
    std::puts("ok pack_with_plugin_id");
}

void test_throw_in_modinfo() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_throw");
    auto path = write_modinfo(root, R"lua(
error("boom from modinfo")
luajit_plugin_pack = true
plugin_id = "never.reached"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(!info.ok);
    assert(!external_pack_trust_ok(info));
    assert(!info.parse_error.empty());
    std::puts("ok throw_in_modinfo");
}

void test_thenet_missing_errors() {
    // Top-level TheNet must not be required; if script calls it and errors, ok=false.
    auto root = make_temp_dir("ds_plugin_pack_modinfo_thenet");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = "vendor.thenet"
if TheNet then
  TheNet:GetIsServer()
end
-- unconditional call: TheNet is nil → should error
TheNet:GetIsServer()
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(!info.ok);
    assert(!external_pack_trust_ok(info));
    assert(!info.parse_error.empty());
    std::puts("ok thenet_missing_errors");
}

void test_folder_name_available() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_folder");
    auto path = write_modinfo(root, R"lua(
-- folder_name is injected; using it must not fail parse
luajit_plugin_pack = true
plugin_id = "vendor." .. tostring(folder_name)
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(info.ok);
    assert(info.luajit_plugin_pack);
    assert(info.plugin_id.find("vendor.") == 0);
    assert(external_pack_trust_ok(info));
    std::puts("ok folder_name_available");
}

void test_empty_plugin_id_not_trusted() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_emptyid");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = ""
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(info.ok);
    assert(info.luajit_plugin_pack);
    assert(info.plugin_id.empty());
    assert(!external_pack_trust_ok(info));
    std::puts("ok empty_plugin_id_not_trusted");
}

void test_non_string_plugin_id_ignored() {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_badid");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = 12345
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    assert(info.ok);
    assert(info.luajit_plugin_pack);
    assert(info.plugin_id.empty());
    assert(!external_pack_trust_ok(info));
    std::puts("ok non_string_plugin_id_ignored");
}

} // namespace

int main() {
    test_missing_file();
    test_no_pack_marker();
    test_pack_without_plugin_id();
    test_pack_with_plugin_id();
    test_throw_in_modinfo();
    test_thenet_missing_errors();
    test_folder_name_available();
    test_empty_plugin_id_not_trusted();
    test_non_string_plugin_id_ignored();
    std::puts("ALL PASS");
    return 0;
}
