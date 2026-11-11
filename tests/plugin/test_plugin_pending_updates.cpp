#include "core/PluginPendingUpdates.hpp"
#include "core/PluginProcessLock.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <doctest/doctest.h>

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

// Removes the scratch tree even when an assertion unwinds the case.
struct TempDirGuard {
    fs::path dir;
    explicit TempDirGuard(const fs::path &d) : dir(d) {}
    ~TempDirGuard() {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
};

static std::string read_all(const fs::path &p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static void write_file(const fs::path &p, const std::string &content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << content;
}

TEST_CASE("test_plugin_pending_updates/empty_or_missing_pending") {
    auto plugins = temp_dir("ds_plugin_pending_empty");
    TempDirGuard guard{plugins};
    REQUIRE_EQ(apply_pending_plugin_updates(plugins), 0);

    auto missing = plugins / "does_not_exist_plugins_root";
    REQUIRE_EQ(apply_pending_plugin_updates(missing), 0);

    fs::create_directories(plugins / "update_pending");
    REQUIRE_EQ(apply_pending_plugin_updates(plugins), 0);
}

TEST_CASE("test_plugin_pending_updates/apply_overwrites_and_clears_pending") {
    auto plugins = temp_dir("ds_plugin_pending_apply");
    TempDirGuard guard{plugins};
    write_file(plugins / "plugin_x" / (std::string("plugin_x") + kModExt), "OLD");
    write_file(plugins / "update_pending" / "plugin_x" / (std::string("plugin_x") + kModExt), "NEW");

    const size_t n = apply_pending_plugin_updates(plugins);
    REQUIRE_GE(n, 1);
    REQUIRE_EQ(read_all(plugins / "plugin_x" / (std::string("plugin_x") + kModExt)), "NEW");
    REQUIRE_FALSE(fs::exists(plugins / "update_pending" / "plugin_x" / (std::string("plugin_x") + kModExt)));
}

TEST_CASE("test_plugin_pending_updates/apply_fresh_install_from_pending") {
    // No existing dest: rename/copy still succeeds without pre-delete.
    auto plugins = temp_dir("ds_plugin_pending_fresh");
    TempDirGuard guard{plugins};
    write_file(plugins / "update_pending" / "plugin_y" / (std::string("plugin_y") + kModExt),
               "FRESH");
    const size_t n = apply_pending_plugin_updates(plugins);
    REQUIRE_GE(n, 1);
    REQUIRE_EQ(read_all(plugins / "plugin_y" / (std::string("plugin_y") + kModExt)), "FRESH");
    REQUIRE_FALSE(fs::exists(plugins / "update_pending" / "plugin_y" / (std::string("plugin_y") + kModExt)));
}

TEST_CASE("test_plugin_pending_updates/ignores_staging_temps") {
    auto plugins = temp_dir("ds_plugin_pending_tmp_ignore");
    TempDirGuard guard{plugins};
    const std::string name = std::string("plugin_z") + kModExt;
    write_file(plugins / "update_pending" / (name + ".ds_pending_tmp_999"), "TEMP");
    write_file(plugins / "update_pending" / "plugin_z" / name, "REAL");
    const size_t n = apply_pending_plugin_updates(plugins);
    REQUIRE_GE(n, 1);
    REQUIRE_EQ(read_all(plugins / "plugin_z" / name), "REAL");
    // Staging leftover may remain; only the real pending should apply.
}

TEST_CASE("test_plugin_pending_updates/translates_legacy_flat_pending") {
    // A flat pending member written by the old flat installer is routed into the package
    // dir; unattributable flat members are ignored (never moved, never deleted).
    auto plugins = temp_dir("ds_plugin_pending_flat_translate");
    TempDirGuard guard{plugins};
    const std::string mod = std::string("plugin_legacy") + kModExt;
    write_file(plugins / "update_pending" / mod, "LEGACY-MOD");
    write_file(plugins / "update_pending" / "plugin_legacy.meta.json", "LEGACY-META");
    write_file(plugins / "update_pending" / "modinfo.lua", "ORPHAN");

    const size_t n = apply_pending_plugin_updates(plugins);
    REQUIRE_EQ(n, 2); // module + meta translated; modinfo.lua ignored
    REQUIRE_EQ(read_all(plugins / "plugin_legacy" / mod), "LEGACY-MOD");
    REQUIRE_EQ(read_all(plugins / "plugin_legacy" / "plugin_legacy.meta.json"), "LEGACY-META");
    REQUIRE_FALSE(fs::exists(plugins / mod)); // never flat
    REQUIRE(fs::exists(plugins / "update_pending" / "modinfo.lua")); // left for the user
}

TEST_CASE("test_plugin_pending_updates/defers_while_another_holder_runs") {
    // A concurrent updater (here: this process holding the tree lock, which also
    // covers the cross-process case) must make the mover defer instead of writing
    // into a tree someone else is mutating. Pending files must survive for the
    // next inject. Costs one kPendingMoveLockTimeoutMs (5 s) of waiting.
    auto plugins = temp_dir("ds_plugin_pending_defer");
    TempDirGuard guard{plugins};
    const std::string name = std::string("plugin_deferred") + kModExt;
    write_file(plugins / "update_pending" / "plugin_deferred" / name, "DEFERRED");

    PluginProcessLock holder;
    std::string err;
    std::string stamp;
    REQUIRE_EQ(holder.acquire(plugins, 0, &err, &stamp), LockResult::Acquired);

    REQUIRE_EQ(apply_pending_plugin_updates(plugins), 0); // deferred, nothing applied
    REQUIRE_FALSE(fs::exists(plugins / "plugin_deferred" / name)); // tree untouched
    REQUIRE(fs::exists(plugins / "update_pending" / "plugin_deferred" / name)); // kept for retry

    holder.release();
    REQUIRE_EQ(apply_pending_plugin_updates(plugins), 1); // next inject applies it
    REQUIRE_EQ(read_all(plugins / "plugin_deferred" / name), "DEFERRED");
}

TEST_CASE("test_plugin_pending_updates/moves_package_members") {
    // Installs mirror the package layout, so pending does too; the mover must rebuild
    // <plugins>/<package>/<member> (and nested Lua members) rather than flattening.
    auto plugins = temp_dir("ds_plugin_pending_pkg");
    TempDirGuard guard{plugins};
    write_file(plugins / "update_pending" / "plugin_pkg" / "plugin_pkg.dll", "PKG");
    write_file(plugins / "update_pending" / "plugin_pkg" / "plugin_pkg.meta.json", "META");
    write_file(plugins / "update_pending" / "plugin_pkg" / "scripts" / "a.lua", "LUA");

    const size_t n = apply_pending_plugin_updates(plugins);
    REQUIRE_EQ(n, 3);
    REQUIRE_EQ(read_all(plugins / "plugin_pkg" / "plugin_pkg.dll"), "PKG");
    REQUIRE_EQ(read_all(plugins / "plugin_pkg" / "plugin_pkg.meta.json"), "META");
    REQUIRE_EQ(read_all(plugins / "plugin_pkg" / "scripts" / "a.lua"), "LUA");
    REQUIRE_FALSE(fs::exists(plugins / "plugin_pkg.dll")); // never flattened
}

TEST_CASE("test_plugin_pending_updates/consolidates_shadowed_flat_modules") {
    auto plugins = temp_dir("ds_plugin_pending_consolidate");
    TempDirGuard guard{plugins};
    // Shadowed: flat + package for the same stem.
    write_file(plugins / (std::string("plugin_shadow") + kModExt), "FLAT");
    write_file(plugins / "plugin_shadow.meta.json", "{}");
    write_file(plugins / "plugin_shadow" / (std::string("plugin_shadow") + kModExt), "PKG");
    // Flat-only (manual drop): must survive.
    write_file(plugins / (std::string("plugin_manual") + kModExt), "MANUAL");

    const size_t removed = consolidate_flat_plugin_layout(plugins);
    REQUIRE_EQ(removed, 2);
    REQUIRE_FALSE(fs::exists(plugins / (std::string("plugin_shadow") + kModExt)));
    REQUIRE_FALSE(fs::exists(plugins / "plugin_shadow.meta.json"));
    REQUIRE(fs::exists(plugins / "plugin_shadow" / (std::string("plugin_shadow") + kModExt)));
    REQUIRE(fs::exists(plugins / (std::string("plugin_manual") + kModExt)));
}
