// Workshop layout gate: modules are published as "<name>.pkg" so the mapped filename is
// never in the item manifest; the runtime materializes the canonical name before load.
#include "core/PackagedModule.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

namespace fs = std::filesystem;

static fs::path temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d);
    return d;
}

static void write_file(const fs::path &p, const std::string &bytes) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
}

static std::string read_file(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

static void test_no_twin_is_a_noop() {
    const auto dir = temp_dir("ds_pkg_notwin");
    const auto canonical = dir / "Injector.dll";
    write_file(canonical, "BUILD");
    assert(!ds::packaged::materialize(canonical));
    assert(read_file(canonical) == "BUILD");
    assert(!ds::packaged::exists_or_materialize(dir / "Missing.dll"));
    printf("PASS: no_twin_is_a_noop\n");
}

static void test_materializes_from_twin() {
    const auto dir = temp_dir("ds_pkg_fresh");
    const auto canonical = dir / "Injector.dll";
    write_file(ds::packaged::packaged_path(canonical), "ITEM");
    assert(ds::packaged::exists_or_materialize(canonical));
    assert(read_file(canonical) == "ITEM");
    // The twin stays: it is the durable published copy.
    assert(read_file(ds::packaged::packaged_path(canonical)) == "ITEM");
    // No staging leftovers.
    assert(!fs::exists(ds::packaged::materialize_temp_path(canonical)));
    printf("PASS: materializes_from_twin\n");
}

static void test_replaces_stale_canonical() {
    const auto dir = temp_dir("ds_pkg_stale");
    const auto canonical = dir / "lua51DS.dll";
    write_file(canonical, "OLD-VM");
    write_file(ds::packaged::packaged_path(canonical), "NEW-VM-BUILD");
    assert(ds::packaged::materialize(canonical));
    assert(read_file(canonical) == "NEW-VM-BUILD");
    printf("PASS: replaces_stale_canonical\n");
}

static void test_identical_twin_does_not_rewrite() {
    const auto dir = temp_dir("ds_pkg_same");
    const auto canonical = dir / "plugin_dummy.dll";
    write_file(canonical, "SAME");
    write_file(ds::packaged::packaged_path(canonical), "SAME");
    const auto before = fs::last_write_time(canonical);
    assert(!ds::packaged::materialize(canonical));
    assert(fs::last_write_time(canonical) == before);
    printf("PASS: identical_twin_does_not_rewrite\n");
}

static void test_materialize_directory() {
    const auto dir = temp_dir("ds_pkg_deps");
    write_file(ds::packaged::packaged_path(dir / "lua51DS.dll"), "VM");
    write_file(ds::packaged::packaged_path(dir / "zlib1.dll"), "ZLIB");
    write_file(dir / "notes.txt", "keep");
    assert(ds::packaged::materialize_directory(dir) == 2);
    assert(read_file(dir / "lua51DS.dll") == "VM");
    assert(read_file(dir / "zlib1.dll") == "ZLIB");
    assert(read_file(dir / "notes.txt") == "keep");
    assert(ds::packaged::materialize_directory(dir / "no_such_dir") == 0);
    printf("PASS: materialize_directory\n");
}

static void test_tree_is_packaged_and_prune() {
    const auto plugins = temp_dir("ds_pkg_tree");
    // Dev tree: no twins anywhere -> never pruned.
    write_file(plugins / "plugin_dev" / "plugin_dev.dll", "DEV");
    assert(!ds::packaged::tree_is_packaged(plugins));
    assert(!ds::packaged::prune_unpackaged_module(plugins, plugins / "plugin_dev" / "plugin_dev.dll"));
    assert(fs::exists(plugins / "plugin_dev" / "plugin_dev.dll"));

    // Packaged tree: a member the item stopped shipping keeps only our derivative.
    write_file(ds::packaged::packaged_path(plugins / "plugin_live" / "plugin_live.dll"), "LIVE");
    assert(ds::packaged::tree_is_packaged(plugins));
    const auto live = plugins / "plugin_live" / "plugin_live.dll";
    const auto dropped = plugins / "plugin_dropped" / "plugin_dropped.dll";
    write_file(live, "LIVE");
    write_file(dropped, "DROPPED");
    assert(!ds::packaged::prune_unpackaged_module(plugins, live)); // twin present -> keep
    assert(fs::exists(live));
    assert(ds::packaged::prune_unpackaged_module(plugins, dropped)); // no twin -> dropped member
    assert(!fs::exists(dropped));
    printf("PASS: tree_is_packaged_and_prune\n");
}

#if defined(_WIN32)
static void test_locked_canonical_is_kept() {
    const auto dir = temp_dir("ds_pkg_locked");
    const auto canonical = dir / "plugin_core_vm.dll";
    write_file(canonical, "IN-USE");
    write_file(ds::packaged::packaged_path(canonical), "NEWER-BUILD");
    // No share flags: models another process holding the image mapped.
    HANDLE h = CreateFileW(canonical.wstring().c_str(), GENERIC_READ, 0, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    assert(h != INVALID_HANDLE_VALUE);
    const bool written = ds::packaged::materialize(canonical);
    CloseHandle(h);
    assert(!written);
    assert(read_file(canonical) == "IN-USE"); // old bytes survive; next boot retries
    assert(!fs::exists(ds::packaged::materialize_temp_path(canonical)));
    printf("PASS: locked_canonical_is_kept\n");
}
#endif

int main() {
    test_no_twin_is_a_noop();
    test_materializes_from_twin();
    test_replaces_stale_canonical();
    test_identical_twin_does_not_rewrite();
    test_materialize_directory();
    test_tree_is_packaged_and_prune();
#if defined(_WIN32)
    test_locked_canonical_is_kept();
#endif
    printf("all packaged module tests passed\n");
    return 0;
}
