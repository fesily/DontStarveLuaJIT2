#include "core/PluginPendingUpdates.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
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

static std::string read_all(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static void write_file(const fs::path &p, const std::string &content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << content;
}

static void test_empty_or_missing_pending() {
    auto plugins = temp_dir("ds_plugin_pending_empty");
    assert(apply_pending_plugin_updates(plugins) == 0);

    auto missing = plugins / "does_not_exist_plugins_root";
    assert(apply_pending_plugin_updates(missing) == 0);

    fs::create_directories(plugins / "update_pending");
    assert(apply_pending_plugin_updates(plugins) == 0);
    printf("PASS: empty_or_missing_pending\n");
}

static void test_apply_overwrites_and_clears_pending() {
    auto plugins = temp_dir("ds_plugin_pending_apply");
#if defined(_WIN32)
    const char *name = "plugin_x.dll";
#else
    const char *name = "plugin_x.so";
#endif
    write_file(plugins / name, "OLD");
    write_file(plugins / "update_pending" / name, "NEW");

    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n >= 1);
    assert(read_all(plugins / name) == "NEW");
    assert(!fs::exists(plugins / "update_pending" / name));
    printf("PASS: apply_overwrites_and_clears_pending\n");
}

static void test_apply_fresh_install_from_pending() {
    // No existing dest: rename/copy still succeeds without pre-delete.
    auto plugins = temp_dir("ds_plugin_pending_fresh");
#if defined(_WIN32)
    const char *name = "plugin_y.dll";
#else
    const char *name = "plugin_y.so";
#endif
    write_file(plugins / "update_pending" / name, "FRESH");
    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n >= 1);
    assert(read_all(plugins / name) == "FRESH");
    assert(!fs::exists(plugins / "update_pending" / name));
    printf("PASS: apply_fresh_install_from_pending\n");
}

static void test_ignores_staging_temps() {
    auto plugins = temp_dir("ds_plugin_pending_tmp_ignore");
#if defined(_WIN32)
    const char *name = "plugin_z.dll";
#else
    const char *name = "plugin_z.so";
#endif
    write_file(plugins / "update_pending" / (std::string(name) + ".ds_pending_tmp_999"), "TEMP");
    write_file(plugins / "update_pending" / name, "REAL");
    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n >= 1);
    assert(read_all(plugins / name) == "REAL");
    // Staging leftover may remain; only the real pending should apply.
    printf("PASS: ignores_staging_temps\n");
}

int main() {
    test_empty_or_missing_pending();
    test_apply_overwrites_and_clears_pending();
    test_apply_fresh_install_from_pending();
    test_ignores_staging_temps();
    printf("ALL PASS plugin_pending_updates\n");
    return 0;
}

