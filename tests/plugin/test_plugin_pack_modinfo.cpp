#include "core/PluginPackModinfo.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <doctest/doctest.h>

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
    const bool written = out.good() || fs::exists(p);
    REQUIRE(written);
    return p;
}

TEST_CASE("test_plugin_pack_modinfo/missing_file") {
    auto missing = fs::temp_directory_path() / "ds_plugin_pack_modinfo_missing" / "modinfo.lua";
    std::error_code ec;
    fs::remove_all(missing.parent_path(), ec);
    auto info = parse_plugin_pack_modinfo(missing);
    REQUIRE_FALSE(info.ok);
    REQUIRE_FALSE(info.luajit_plugin_pack);
    REQUIRE(info.plugin_id.empty());
    REQUIRE_EQ(info.parse_error, "open_failed");
    REQUIRE_FALSE(external_pack_trust_ok(info));
}

TEST_CASE("test_plugin_pack_modinfo/no_pack_marker") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_nopack");
    auto path = write_modinfo(root, R"lua(
name = "Plain Mod"
description = "no pack marker"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE(info.ok);
    REQUIRE_FALSE(info.luajit_plugin_pack);
    REQUIRE(info.plugin_id.empty());
    REQUIRE(info.parse_error.empty());
    REQUIRE_FALSE(external_pack_trust_ok(info));
}

TEST_CASE("test_plugin_pack_modinfo/pack_without_plugin_id") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_noid");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
name = "Pack Missing Id"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE(info.ok);
    REQUIRE(info.luajit_plugin_pack);
    REQUIRE(info.plugin_id.empty());
    REQUIRE_FALSE(external_pack_trust_ok(info));
}

TEST_CASE("test_plugin_pack_modinfo/pack_with_plugin_id") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_ok");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = "vendor.x"
name = "Trusted Pack"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE(info.ok);
    REQUIRE(info.luajit_plugin_pack);
    REQUIRE_EQ(info.plugin_id, "vendor.x");
    REQUIRE(info.parse_error.empty());
    REQUIRE(external_pack_trust_ok(info));
}

TEST_CASE("test_plugin_pack_modinfo/throw_in_modinfo") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_throw");
    auto path = write_modinfo(root, R"lua(
error("boom from modinfo")
luajit_plugin_pack = true
plugin_id = "never.reached"
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE_FALSE(info.ok);
    REQUIRE_FALSE(external_pack_trust_ok(info));
    REQUIRE_FALSE(info.parse_error.empty());
}

TEST_CASE("test_plugin_pack_modinfo/thenet_missing_errors") {
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
    REQUIRE_FALSE(info.ok);
    REQUIRE_FALSE(external_pack_trust_ok(info));
    REQUIRE_FALSE(info.parse_error.empty());
}

TEST_CASE("test_plugin_pack_modinfo/folder_name_available") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_folder");
    auto path = write_modinfo(root, R"lua(
-- folder_name is injected; using it must not fail parse
luajit_plugin_pack = true
plugin_id = "vendor." .. tostring(folder_name)
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE(info.ok);
    REQUIRE(info.luajit_plugin_pack);
    REQUIRE_EQ(info.plugin_id.find("vendor."), 0);
    REQUIRE(external_pack_trust_ok(info));
}

TEST_CASE("test_plugin_pack_modinfo/empty_plugin_id_not_trusted") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_emptyid");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = ""
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE(info.ok);
    REQUIRE(info.luajit_plugin_pack);
    REQUIRE(info.plugin_id.empty());
    REQUIRE_FALSE(external_pack_trust_ok(info));
}

TEST_CASE("test_plugin_pack_modinfo/non_string_plugin_id_ignored") {
    auto root = make_temp_dir("ds_plugin_pack_modinfo_badid");
    auto path = write_modinfo(root, R"lua(
luajit_plugin_pack = true
plugin_id = 12345
)lua");
    auto info = parse_plugin_pack_modinfo(path);
    REQUIRE(info.ok);
    REQUIRE(info.luajit_plugin_pack);
    REQUIRE(info.plugin_id.empty());
    REQUIRE_FALSE(external_pack_trust_ok(info));
}

} // namespace
