#include "core/ExternalPluginDiscovery.hpp"

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

void touch(const fs::path &p) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << "x";
}

TEST_CASE("test_external_plugin_discovery/path_under_root_accepts_child") {
    auto root = make_temp_dir("ds_ext_disc_root_ok");
    auto child = root / "plugins" / "plugin_x" / "plugin_x.dll";
    touch(child);
    REQUIRE(path_under_root(root, child));
}

TEST_CASE("test_external_plugin_discovery/path_under_root_rejects_escape") {
    auto root = make_temp_dir("ds_ext_disc_root_esc");
    auto outside = root.parent_path() / "ds_ext_disc_evil" / "evil.dll";
    touch(outside);
    // Construct a path that lexically escapes then normalizes outside.
    auto escaped = root / "plugins" / ".." / ".." / outside.filename();
    // Even if file doesn't exist at escaped, jail uses weakly_canonical.
    // Use outside absolute path which is not under root.
    REQUIRE_FALSE(path_under_root(root, outside));
}

TEST_CASE("test_external_plugin_discovery/list_pack_modules_finds_package_dll") {
    auto root = make_temp_dir("ds_ext_disc_list_ok");
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    auto good = root / "plugins" / "plugin_x" / (std::string("plugin_x") + ext);
    touch(good);
    // noise
    touch(root / "plugins" / "readme.txt");
    touch(root / "plugins" / "plugin_y" / "not_matching.dll");
    auto mods = list_pack_modules_under_mod(root);
    REQUIRE_EQ(mods.size(), 1);
    REQUIRE_NE(mods[0].filename().string().find("plugin_x"), std::string::npos);
}

TEST_CASE("test_external_plugin_discovery/list_pack_modules_empty_without_plugins") {
    auto root = make_temp_dir("ds_ext_disc_list_empty");
    auto mods = list_pack_modules_under_mod(root);
    REQUIRE(mods.empty());
}

TEST_CASE("test_external_plugin_discovery/list_ignores_non_plugin_prefix_dirs") {
    auto root = make_temp_dir("ds_ext_disc_list_prefix");
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    touch(root / "plugins" / "other_x" / (std::string("other_x") + ext));
    auto mods = list_pack_modules_under_mod(root);
    REQUIRE(mods.empty());
}

} // namespace
