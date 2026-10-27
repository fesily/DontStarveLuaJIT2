#include "core/DynamicPluginLoader.hpp"
#include "core/PluginHost.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
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

static void test_empty_dir() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_empty");
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    assert(r.skipped.empty());
    printf("PASS: empty_dir\n");
}

static void test_non_plugin_file_ignored() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_noise");
    std::ofstream(dir / "readme.txt") << "x";
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    printf("PASS: noise_ignored\n");
}

static void test_flat_module_ignored() {
    // Flat plugin modules are unsupported: never attempted, and never reported as a load
    // failure (they are simply not candidates). Files must live in plugins/<stem>/.
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_flat");
#if defined(_WIN32)
    auto bad = dir / "plugin_notalib.dll";
#else
    auto bad = dir / "plugin_notalib.so";
#endif
    std::ofstream(bad, std::ios::binary) << "not a pe/elf";
    auto r = loader.load_directory(host, dir);
    assert(r.loaded_modules.empty());
    assert(r.skipped.empty());
    printf("PASS: flat_module_ignored\n");
}

static void test_package_subdir_bad_library_skipped() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_pkg");
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
    assert(r.loaded_modules.empty());
    assert(!r.skipped.empty());
    printf("PASS: package_subdir_bad_library_skipped\n");
}


// Workshop layout: the item ships "<module>.pkg" only. The candidate must be materialized
// (canonical name) before the load attempt — the loader never opens the twin itself.
static void test_packaged_twin_materialized_before_load() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_twin");
#if defined(_WIN32)
    const char *ext = ".dll";
#else
    const char *ext = ".so";
#endif
    auto pkg = dir / "plugin_pkgonly";
    fs::create_directories(pkg);
    const auto canonical = pkg / (std::string("plugin_pkgonly") + ext);
    std::ofstream(canonical.string() + ".pkg", std::ios::binary) << "not a pe/elf";
    assert(!fs::exists(canonical));

    auto r = loader.load_directory(host, dir);
    assert(fs::exists(canonical));      // materialized from the twin
    assert(r.loaded_modules.empty());   // garbage payload: attempted and refused
    assert(!r.skipped.empty());
    printf("PASS: packaged_twin_materialized_before_load\n");
}

// A stale canonical must not shadow a replaced twin: the replacement is compared and
// materialized before the load attempt instead of mapping the previous build's derivative.
static void test_packaged_twin_refreshes_stale_canonical() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_twin_stale");
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
    assert(materialized == "replaced item payload");
    assert(r.loaded_modules.empty()); // garbage payload: attempted and refused
    assert(!r.skipped.empty());
    printf("PASS: packaged_twin_refreshes_stale_canonical\n");
}

// Package dir + flat module for one stem: the flat copy is not a candidate at all, so
// only the package copy is attempted (one stemming from the folder layout only).
static void test_flat_ignored_beside_package() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto dir = temp_dir("ds_plugin_loader_pref");
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
    assert(r.loaded_modules.empty());
    const std::string flat = (dir / (std::string("plugin_notalib") + ext)).string();
    const std::string packaged = (pkg / (std::string("plugin_notalib") + ext)).string();
    bool package_attempted = false;
    for (const auto &entry : r.skipped) {
        if (entry.find(flat) != std::string::npos) {
            assert(false && "flat module must never be attempted");
        }
        if (entry.find(packaged) != std::string::npos) {
            package_attempted = true;
        }
    }
    assert(package_attempted);
    printf("PASS: flat_ignored_beside_package\n");
}

// Two plugins roots can carry the same package (mod-local tree + the
// injector_module_dir() migration fallback). Initializing the second copy
// re-registers the plugin's services; the loader must handle one copy per stem,
// first root wins, and still pick up stems the first root did not have.
static void test_duplicate_stem_across_roots() {
    PluginHost host;
    DynamicPluginLoader loader;
    auto root1 = temp_dir("ds_plugin_loader_root1");
    auto root2 = temp_dir("ds_plugin_loader_root2");
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
    assert(r1.loaded_modules.empty());
    assert(!r1.skipped.empty()); // garbage payload: attempted and refused

    auto r2 = loader.load_directory(host, root2);
    assert(r2.loaded_modules.empty());
    const std::string dupe2 = (root2 / "plugin_dupe" / (std::string("plugin_dupe") + ext)).string();
    const std::string only2 = (root2 / "plugin_only2" / (std::string("plugin_only2") + ext)).string();
    bool dupe_skipped = false;
    bool only2_attempted = false;
    for (const auto &entry : r2.skipped) {
        if (entry.find(dupe2) != std::string::npos) {
            assert(entry.find("duplicate_stem") != std::string::npos);
            dupe_skipped = true;
        }
        if (entry.find(only2) != std::string::npos) {
            assert(entry.find("duplicate_stem") == std::string::npos);
            only2_attempted = true;
        }
    }
    assert(dupe_skipped);
    assert(only2_attempted);
    printf("PASS: duplicate_stem_across_roots\n");
}

int main() {
    test_empty_dir();
    test_non_plugin_file_ignored();
    test_flat_module_ignored();
    test_package_subdir_bad_library_skipped();
    test_packaged_twin_materialized_before_load();
    test_packaged_twin_refreshes_stale_canonical();
    test_flat_ignored_beside_package();
    test_duplicate_stem_across_roots();
    // Real plugin_dummy load is skipped here: MODULE imports Injector.dll
    // (and its transitive deps). Under Inject() Injector is already mapped so
    // LoadLibrary binds cleanly; a bare unit EXE cannot satisfy that graph.
    printf("ALL PASS dynamic_plugin_loader\n");
    return 0;
}
