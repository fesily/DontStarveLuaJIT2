#include "core/DynamicPluginLoader.hpp"
#include "core/PluginHost.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
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

// Removes the scratch tree even when an assertion unwinds the case.
struct TempDirGuard {
    fs::path dir;
    explicit TempDirGuard(const fs::path &d) : dir(d) {}
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

TEST_CASE("test_dynamic_plugin_loader/empty_dir") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_empty");
    TempDirGuard guard{dir};
    auto r = loader.load_directory(host, dir);
    REQUIRE(r.loaded_modules.empty());
    REQUIRE(r.skipped.empty());
}

TEST_CASE("test_dynamic_plugin_loader/non_plugin_file_ignored") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_noise");
    TempDirGuard guard{dir};
    std::ofstream(dir / "readme.txt") << "x";
    auto r = loader.load_directory(host, dir);
    REQUIRE(r.loaded_modules.empty());
}

TEST_CASE("test_dynamic_plugin_loader/flat_module_ignored") {
    // Flat plugin modules are unsupported: never attempted, and never reported as a load
    // failure (they are simply not candidates). Files must live in plugins/<stem>/.
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_flat");
    TempDirGuard guard{dir};
#if defined(_WIN32)
    auto bad = dir / "plugin_notalib.dll";
#else
    auto bad = dir / "plugin_notalib.so";
#endif
    std::ofstream(bad, std::ios::binary) << "not a pe/elf";
    auto r = loader.load_directory(host, dir);
    REQUIRE(r.loaded_modules.empty());
    REQUIRE(r.skipped.empty());
}

TEST_CASE("test_dynamic_plugin_loader/package_subdir_bad_library_skipped") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_pkg");
    TempDirGuard guard{dir};
    auto pkg = dir / "plugin_notalib";
    fs::create_directories(pkg);
#if defined(_WIN32)
    auto bad = pkg / "plugin_notalib.dll";
#else
    auto bad = pkg / "plugin_notalib.so";
#endif
    std::ofstream(bad, std::ios::binary) << "not a pe/elf";
    std::ofstream(pkg / "modinfo.lua") << "name='x'\n";
    auto r = loader.load_directory(host, dir);
    REQUIRE(r.loaded_modules.empty());
    REQUIRE_FALSE(r.skipped.empty());
}


// Workshop layout: the item ships "<module>.pkg" only. The candidate must be materialized
// (canonical name) before the load attempt — the loader never opens the twin itself.
TEST_CASE("test_dynamic_plugin_loader/packaged_twin_materialized_before_load") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_twin");
    TempDirGuard guard{dir};
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    auto pkg = dir / "plugin_pkgonly";
    fs::create_directories(pkg);
    const auto canonical = pkg / (std::string("plugin_pkgonly") + ext);
    std::ofstream(canonical.string() + ".pkg", std::ios::binary) << "not a pe/elf";
    REQUIRE_FALSE(fs::exists(canonical));

    auto r = loader.load_directory(host, dir);
    REQUIRE(fs::exists(canonical));      // materialized from the twin
    REQUIRE(r.loaded_modules.empty());   // garbage payload: attempted and refused
    REQUIRE_FALSE(r.skipped.empty());
}

// A stale canonical must not shadow a replaced twin: the replacement is compared and
// materialized before the load attempt instead of mapping the previous build's derivative.
TEST_CASE("test_dynamic_plugin_loader/packaged_twin_refreshes_stale_canonical") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_twin_stale");
    TempDirGuard guard{dir};
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    auto pkg = dir / "plugin_pkgswap";
    fs::create_directories(pkg);
    const auto canonical = pkg / (std::string("plugin_pkgswap") + ext);
    std::ofstream(canonical, std::ios::binary) << "stale derivative";
    std::ofstream(canonical.string() + ".pkg", std::ios::binary) << "replaced item payload";

    auto r = loader.load_directory(host, dir);
    std::ifstream in(canonical, std::ios::binary);
    const std::string materialized((std::istreambuf_iterator<char>(in)),
                                   std::istreambuf_iterator<char>());
    REQUIRE_EQ(materialized, "replaced item payload");
    REQUIRE(r.loaded_modules.empty()); // garbage payload: attempted and refused
    REQUIRE_FALSE(r.skipped.empty());
}

// Package dir + flat module for one stem: the flat copy is not a candidate at all, so
// only the package copy is attempted (one stemming from the folder layout only).
TEST_CASE("test_dynamic_plugin_loader/flat_ignored_beside_package") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_pref");
    TempDirGuard guard{dir};
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    auto pkg = dir / "plugin_notalib";
    fs::create_directories(pkg);
    std::ofstream(pkg / (std::string("plugin_notalib") + ext), std::ios::binary) << "not a pe/elf";
    std::ofstream(dir / (std::string("plugin_notalib") + ext), std::ios::binary) << "not a pe/elf";

    auto r = loader.load_directory(host, dir);
    REQUIRE(r.loaded_modules.empty());
    const std::string flat = (dir / (std::string("plugin_notalib") + ext)).string();
    const std::string packaged = (pkg / (std::string("plugin_notalib") + ext)).string();
    bool package_attempted = false;
    for (const auto &entry : r.skipped) {
        if (entry.find(flat) != std::string::npos) {
            FAIL("flat module must never be attempted");
        }
        if (entry.find(packaged) != std::string::npos) {
            package_attempted = true;
        }
    }
    REQUIRE(package_attempted);
}

// Two plugins roots can carry the same package (mod-local tree + the
// injector_module_dir() migration fallback). Initializing the second copy
// re-registers the plugin's services; the loader must handle one copy per stem,
// first root wins, and still pick up stems the first root did not have.
TEST_CASE("test_dynamic_plugin_loader/duplicate_stem_across_roots") {
    PluginHost host;
    DynamicPluginLoader loader;
    auto root1 = temp_dir("ds_plugin_loader_root1");
    TempDirGuard guard1{root1};
    auto root2 = temp_dir("ds_plugin_loader_root2");
    TempDirGuard guard2{root2};
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    auto make_pkg = [ext](const fs::path &root, const char *stem) {
        auto pkg = root / stem;
        fs::create_directories(pkg);
        std::ofstream(pkg / (std::string(stem) + ext), std::ios::binary) << "not a pe/elf";
    };
    make_pkg(root1, "plugin_dupe");
    make_pkg(root2, "plugin_dupe");
    make_pkg(root2, "plugin_only2");

    auto r1 = loader.load_directory(host, root1);
    REQUIRE(r1.loaded_modules.empty());
    REQUIRE_FALSE(r1.skipped.empty()); // garbage payload: attempted and refused

    auto r2 = loader.load_directory(host, root2);
    REQUIRE(r2.loaded_modules.empty());
    const std::string dupe2 = (root2 / "plugin_dupe" / (std::string("plugin_dupe") + ext)).string();
    const std::string only2 = (root2 / "plugin_only2" / (std::string("plugin_only2") + ext)).string();
    bool dupe_skipped = false;
    bool only2_attempted = false;
    for (const auto &entry : r2.skipped) {
        if (entry.find(dupe2) != std::string::npos) {
            REQUIRE_NE(entry.find("duplicate_stem"), std::string::npos);
            dupe_skipped = true;
        }
        if (entry.find(only2) != std::string::npos) {
            REQUIRE_EQ(entry.find("duplicate_stem"), std::string::npos);
            only2_attempted = true;
        }
    }
    REQUIRE(dupe_skipped);
    REQUIRE(only2_attempted);
}

// Real plugin_dummy load is skipped here: MODULE imports Injector.dll
// (and its transitive deps). Under Inject() Injector is already mapped so
// LoadLibrary binds cleanly; a bare unit EXE cannot satisfy that graph.
