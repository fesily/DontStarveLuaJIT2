#include "core/PluginPendingUpdates.hpp"
#include "core/PluginProcessLock.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace ds::plugin;
namespace fs = std::filesystem;

#if defined(_WIN32)
static const char *kModExt = ".dll";
#else
static const char *kModExt = ".so";
#endif

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
    write_file(plugins / "plugin_x" / (std::string("plugin_x") + kModExt), "OLD");
    write_file(plugins / "update_pending" / "plugin_x" / (std::string("plugin_x") + kModExt), "NEW");

    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n >= 1);
    assert(read_all(plugins / "plugin_x" / (std::string("plugin_x") + kModExt)) == "NEW");
    assert(!fs::exists(plugins / "update_pending" / "plugin_x" / (std::string("plugin_x") + kModExt)));
    printf("PASS: apply_overwrites_and_clears_pending\n");
}

static void test_apply_fresh_install_from_pending() {
    // No existing dest: rename/copy still succeeds without pre-delete.
    auto plugins = temp_dir("ds_plugin_pending_fresh");
    write_file(plugins / "update_pending" / "plugin_y" / (std::string("plugin_y") + kModExt),
               "FRESH");
    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n >= 1);
    assert(read_all(plugins / "plugin_y" / (std::string("plugin_y") + kModExt)) == "FRESH");
    assert(!fs::exists(plugins / "update_pending" / "plugin_y" / (std::string("plugin_y") + kModExt)));
    printf("PASS: apply_fresh_install_from_pending\n");
}

static void test_ignores_staging_temps() {
    auto plugins = temp_dir("ds_plugin_pending_tmp_ignore");
    const std::string name = std::string("plugin_z") + kModExt;
    write_file(plugins / "update_pending" / (name + ".ds_pending_tmp_999"), "TEMP");
    write_file(plugins / "update_pending" / "plugin_z" / name, "REAL");
    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n >= 1);
    assert(read_all(plugins / "plugin_z" / name) == "REAL");
    // Staging leftover may remain; only the real pending should apply.
    printf("PASS: ignores_staging_temps\n");
}

static void test_translates_legacy_flat_pending() {
    // A flat pending member written by the old flat installer is routed into the package
    // dir; unattributable flat members are ignored (never moved, never deleted).
    auto plugins = temp_dir("ds_plugin_pending_flat_translate");
    const std::string mod = std::string("plugin_legacy") + kModExt;
    write_file(plugins / "update_pending" / mod, "LEGACY-MOD");
    write_file(plugins / "update_pending" / "plugin_legacy.meta.json", "LEGACY-META");
    write_file(plugins / "update_pending" / "modinfo.lua", "ORPHAN");

    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n == 2); // module + meta translated; modinfo.lua ignored
    assert(read_all(plugins / "plugin_legacy" / mod) == "LEGACY-MOD");
    assert(read_all(plugins / "plugin_legacy" / "plugin_legacy.meta.json") == "LEGACY-META");
    assert(!fs::exists(plugins / mod)); // never flat
    assert(fs::exists(plugins / "update_pending" / "modinfo.lua")); // left for the user
    printf("PASS: translates_legacy_flat_pending\n");
}

static void test_defers_while_another_holder_runs() {
    // A concurrent updater (here: this process holding the tree lock, which also
    // covers the cross-process case) must make the mover defer instead of writing
    // into a tree someone else is mutating. Pending files must survive for the
    // next inject. Costs one kPendingMoveLockTimeoutMs (5 s) of waiting.
    auto plugins = temp_dir("ds_plugin_pending_defer");
    const std::string name = std::string("plugin_deferred") + kModExt;
    write_file(plugins / "update_pending" / "plugin_deferred" / name, "DEFERRED");

    PluginProcessLock holder;
    std::string err;
    std::string stamp;
    assert(holder.acquire(plugins, 0, &err, &stamp) == LockResult::Acquired);

    assert(apply_pending_plugin_updates(plugins) == 0); // deferred, nothing applied
    assert(!fs::exists(plugins / "plugin_deferred" / name)); // tree untouched
    assert(fs::exists(plugins / "update_pending" / "plugin_deferred" / name)); // kept for retry

    holder.release();
    assert(apply_pending_plugin_updates(plugins) == 1); // next inject applies it
    assert(read_all(plugins / "plugin_deferred" / name) == "DEFERRED");
    printf("PASS: defers_while_another_holder_runs\n");
}

static void test_moves_package_members() {
    // Installs mirror the package layout, so pending does too; the mover must rebuild
    // <plugins>/<package>/<member> (and nested Lua members) rather than flattening.
    auto plugins = temp_dir("ds_plugin_pending_pkg");
    write_file(plugins / "update_pending" / "plugin_pkg" / "plugin_pkg.dll", "PKG");
    write_file(plugins / "update_pending" / "plugin_pkg" / "plugin_pkg.meta.json", "META");
    write_file(plugins / "update_pending" / "plugin_pkg" / "scripts" / "a.lua", "LUA");

    const size_t n = apply_pending_plugin_updates(plugins);
    assert(n == 3);
    assert(read_all(plugins / "plugin_pkg" / "plugin_pkg.dll") == "PKG");
    assert(read_all(plugins / "plugin_pkg" / "plugin_pkg.meta.json") == "META");
    assert(read_all(plugins / "plugin_pkg" / "scripts" / "a.lua") == "LUA");
    assert(!fs::exists(plugins / "plugin_pkg.dll")); // never flattened
    printf("PASS: moves_package_members\n");
}

static void test_consolidates_shadowed_flat_modules() {
    auto plugins = temp_dir("ds_plugin_pending_consolidate");
    // Shadowed: flat + package for the same stem.
    write_file(plugins / (std::string("plugin_shadow") + kModExt), "FLAT");
    write_file(plugins / "plugin_shadow.meta.json", "{}");
    write_file(plugins / "plugin_shadow" / (std::string("plugin_shadow") + kModExt), "PKG");
    // Flat-only (manual drop): must survive.
    write_file(plugins / (std::string("plugin_manual") + kModExt), "MANUAL");

    const size_t removed = consolidate_flat_plugin_layout(plugins);
    assert(removed == 2);
    assert(!fs::exists(plugins / (std::string("plugin_shadow") + kModExt)));
    assert(!fs::exists(plugins / "plugin_shadow.meta.json"));
    assert(fs::exists(plugins / "plugin_shadow" / (std::string("plugin_shadow") + kModExt)));
    assert(fs::exists(plugins / (std::string("plugin_manual") + kModExt)));
    printf("PASS: consolidates_shadowed_flat_modules\n");
}

int main() {
    test_empty_or_missing_pending();
    test_apply_overwrites_and_clears_pending();
    test_apply_fresh_install_from_pending();
    test_ignores_staging_temps();
    test_translates_legacy_flat_pending();
    test_defers_while_another_holder_runs();
    test_moves_package_members();
    test_consolidates_shadowed_flat_modules();
    printf("ALL PASS plugin_pending_updates\n");
    return 0;
}

