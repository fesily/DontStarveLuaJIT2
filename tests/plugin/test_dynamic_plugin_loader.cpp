#include "core/DynamicPluginLoader.hpp"
#include "core/PluginHost.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>

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

int main() {
    test_empty_dir();
    test_non_plugin_file_ignored();
    test_flat_module_ignored();
    test_package_subdir_bad_library_skipped();
    test_flat_ignored_beside_package();
    // Real plugin_dummy load is skipped here: MODULE imports Injector.dll
    // (and its transitive deps). Under Inject() Injector is already mapped so
    // LoadLibrary binds cleanly; a bare unit EXE cannot satisfy that graph.
    printf("ALL PASS dynamic_plugin_loader\n");
    return 0;
}
