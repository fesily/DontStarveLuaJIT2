// Workshop layout gate: modules are published as "<name>.pkg" so the mapped filename is
// never in the item manifest; the runtime materializes the canonical name before load.
#include "core/PackagedModule.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

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

static std::string platform_module_name(const char *stem) {
#if defined(_WIN32)
    return std::string{stem} + ".dll";
#elif defined(__APPLE__)
    return std::string{stem} + ".dylib";
#else
    return std::string{stem} + ".so";
#endif
}

static void test_tree_is_packaged_and_prune() {
    const auto plugins = temp_dir("ds_pkg_tree");
    // Dev tree: no twins anywhere -> never pruned.
    const auto dev = plugins / "plugin_dev" / platform_module_name("plugin_dev");
    write_file(dev, "DEV");
    assert(!ds::packaged::tree_is_packaged(plugins));
    assert(!ds::packaged::prune_unpackaged_module(plugins, dev));
    assert(fs::exists(dev));

    // Packaged tree: a member the item stopped shipping keeps only our derivative.
    write_file(ds::packaged::packaged_path(
                       plugins / "plugin_live" / platform_module_name("plugin_live")), "LIVE");
    assert(ds::packaged::tree_is_packaged(plugins));
    const auto live = plugins / "plugin_live" / platform_module_name("plugin_live");
    const auto dropped = plugins / "plugin_dropped" / platform_module_name("plugin_dropped");
    write_file(live, "LIVE");
    write_file(dropped, "DROPPED");
    assert(!ds::packaged::prune_unpackaged_module(plugins, live)); // twin present -> keep
    assert(fs::exists(live));
    assert(ds::packaged::prune_unpackaged_module(plugins, dropped)); // no twin -> dropped member
    assert(!fs::exists(dropped));
    printf("PASS: tree_is_packaged_and_prune\n");
}

// A real, complete image (this test binary: PE on Windows, ELF elsewhere) so "torn
// copy" checks exercise the platform's validator.
static fs::path self_image() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    assert(n != 0 && n < MAX_PATH);
    return fs::path(buf);
#else
    return fs::path("/proc/self/exe");
#endif
}

static size_t count_temp_files(const fs::path &dir) {
    size_t n = 0;
    for (const auto &entry : fs::directory_iterator(dir)) {
        if (entry.path().filename().string().find(ds::packaged::kMaterializeTempSuffix) !=
            std::string::npos) {
            ++n;
        }
    }
    return n;
}

// Concurrent materialize of the same module (client + Master + Caves booting together):
// every writer stages into a private temp and only the atomic replace publishes, so the
// canonical file is never missing or half-written and no temp is left behind.
static void test_concurrent_materialize_is_safe() {
    const auto dir = temp_dir("ds_pkg_race");
    const auto canonical = dir / "Injector.dll";
    fs::copy_file(self_image(), ds::packaged::packaged_path(canonical));
    assert(!fs::exists(canonical));
    const auto expected = fs::file_size(self_image());

    // Transient open failures are legitimate while a peer swaps the name; a *wrong size*
    // (a half-published file) is the corruption this guards against.
    auto published_ok = [&] {
        for (int attempt = 0; attempt < 20; ++attempt) {
            std::error_code ec;
            const auto size = fs::file_size(canonical, ec);
            if (!ec) {
                return size == expected;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return false;
    };

    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    threads.reserve(8);
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 25; ++i) {
                (void)ds::packaged::materialize(canonical);
                if (!published_ok()) {
                    ++failures;
                }
            }
        });
    }
    for (auto &th : threads) {
        th.join();
    }
    assert(failures.load() == 0);
    assert(fs::file_size(canonical) == fs::file_size(self_image()));
    assert(count_temp_files(dir) == 0);
    printf("PASS: concurrent_materialize_is_safe\n");
}

// An item update rewriting the twin can hand us a half-written file: refuse to publish it
// (a truncated PE has sections past EOF) instead of clobbering a working canonical.
static void test_torn_twin_is_refused() {
    const auto dir = temp_dir("ds_pkg_torn");
    const auto canonical = dir / "lua51DS.dll";
    write_file(canonical, "WORKING-OLD");
    const auto twin = ds::packaged::packaged_path(canonical);
    fs::copy_file(self_image(), twin);
    const auto full = fs::file_size(twin);
    fs::resize_file(twin, full / 2); // keep the headers, cut the payload

    assert(!ds::packaged::materialize(canonical));
    assert(read_file(canonical) == "WORKING-OLD");
    assert(count_temp_files(dir) == 0);
    printf("PASS: torn_twin_is_refused\n");
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
    test_concurrent_materialize_is_safe();
    test_torn_twin_is_refused();
#if defined(_WIN32)
    test_locked_canonical_is_kept();
#endif
    printf("all packaged module tests passed\n");
    return 0;
}
