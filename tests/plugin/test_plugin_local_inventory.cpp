#include "core/PluginPath.hpp"
#include "plugins/plugin_manager/PluginLocalInventory.hpp"
#include "plugins/plugin_manager/PluginPinConfig.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
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

static void write_text(const fs::path &p, const std::string &body) {
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.is_open());
    out << body;
    REQUIRE(out);
}

static void set_env(const char *k, const char *v) {
#if defined(_WIN32)
    _putenv_s(k, v ? v : "");
#else
    if (!v || !*v)
        unsetenv(k);
    else
        setenv(k, v, 1);
#endif
}

TEST_CASE("test_plugin_local_inventory/resolve_plugins_dir_has_no_fallback") {
    auto base = temp_dir("ds_plugin_inv_root");
    auto mod = base / "mod";
    auto plugins = mod / "plugins";
    fs::create_directories(plugins);
    auto file = base / "not_a_dir";
    write_text(file, "x");

    // No override: the manager sees exactly the loader's root.
    set_env(ds::plugin::kPluginDirEnv, "");
    ds::plugin::set_injector_module_dir_for_test(mod);
    const auto root = ds::plugin::resolve_plugins_dir();

    // Broken override: no root and no module-relative fallback (the manager must
    // not scan/apply into a tree the loader refuses).
    set_env(ds::plugin::kPluginDirEnv, file.string().c_str());
    const auto broken = ds::plugin::resolve_plugins_dir();

    set_env(ds::plugin::kPluginDirEnv, "");
    ds::plugin::set_injector_module_dir_for_test(fs::path{});
    fs::remove_all(base);

    REQUIRE_EQ(root, plugins);
    REQUIRE(broken.empty());
}

// Package layout is the only supported one: fixtures write plugins/<stem>/<member>.
static void write_pkg_text(const fs::path &plugins_dir, const char *stem, const char *member,
                           const std::string &body) {
    const auto p = plugins_dir / stem / member;
    fs::create_directories(p.parent_path());
    write_text(p, body);
}

TEST_CASE("test_plugin_local_inventory/scan_meta_and_module") {
    auto dir = temp_dir("ds_plugin_inv_meta");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.meta.json",
               R"({
  "id": "debug.dummy",
  "version": "1.2.3",
  "sha256": "abc123",
  "module": "plugin_dummy.dll"
}
)");
    // Fake module binary (content irrelevant for inventory).
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.dll", "MZ-fake");

    auto inv = scan_local_inventory(dir);
    REQUIRE_EQ(inv.size(), 1);
    REQUIRE_EQ(inv[0].id, "debug.dummy");
    REQUIRE(inv[0].version.has_value());
    REQUIRE_EQ(*inv[0].version, "1.2.3");
    REQUIRE(inv[0].sha256.has_value());
    REQUIRE_EQ(*inv[0].sha256, "abc123");
    REQUIRE_EQ(inv[0].module, "plugin_dummy.dll");
    REQUIRE(inv[0].has_meta);
    REQUIRE(inv[0].has_module);
}

TEST_CASE("test_plugin_local_inventory/module_without_meta_version_unknown") {
    auto dir = temp_dir("ds_plugin_inv_nometa");
    write_pkg_text(dir, "plugin_core_vm", "plugin_core_vm.dll", "MZ-fake");

    auto inv = scan_local_inventory(dir);
    REQUIRE_EQ(inv.size(), 1);
    REQUIRE_EQ(inv[0].id, "core.vm"); // mapped stem
    REQUIRE_FALSE(inv[0].version.has_value());
    REQUIRE(inv[0].has_module);
    REQUIRE_FALSE(inv[0].has_meta);
}

TEST_CASE("test_plugin_local_inventory/missing_dir_empty") {
    auto inv = scan_local_inventory(fs::temp_directory_path() / "ds_plugin_inv_missing_xyz");
    REQUIRE(inv.empty());
}

TEST_CASE("test_plugin_local_inventory/status_override_update_available") {
    auto dir = temp_dir("ds_plugin_inv_status");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"1.0.0","sha256":"x","module":"plugin_dummy.dll"})");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    cfg.pins["debug.dummy"] = PinEntry{"2.0.0", "override"};

    auto inv = scan_local_inventory(dir);
    auto rows = build_plugin_status(cfg, inv);
    REQUIRE_EQ(rows.size(), 1);
    REQUIRE_EQ(rows[0].id, "debug.dummy");
    REQUIRE(rows[0].local_version.has_value());
    REQUIRE_EQ(*rows[0].local_version, "1.0.0");
    REQUIRE(rows[0].desired_version.has_value());
    REQUIRE_EQ(*rows[0].desired_version, "2.0.0");
    REQUIRE(rows[0].pin_source.has_value());
    REQUIRE_EQ(*rows[0].pin_source, "override");
    REQUIRE_EQ(rows[0].state, "update_available");
    REQUIRE_FALSE(rows[0].channel_version.has_value());
}

TEST_CASE("test_plugin_local_inventory/status_local_only_ok") {
    auto dir = temp_dir("ds_plugin_inv_ok");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"1.0.0","module":"plugin_dummy.dll"})");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    auto inv = scan_local_inventory(dir);
    auto rows = build_plugin_status(cfg, inv);
    REQUIRE_EQ(rows.size(), 1);
    REQUIRE_EQ(rows[0].state, "ok");
    REQUIRE_FALSE(rows[0].desired_version.has_value());
}

TEST_CASE("test_plugin_local_inventory/plan_mismatch_and_prefer_present") {
    auto dir = temp_dir("ds_plugin_inv_plan");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"1.0.0","module":"plugin_dummy.dll"})");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    cfg.pins["debug.dummy"] = PinEntry{"9.9.9", "override"};
    cfg.prefer_present.push_back("network.rpc"); // missing soft preference

    auto inv = scan_local_inventory(dir);
    auto plan = build_plan_actions(cfg, inv);
    REQUIRE_EQ(plan.size(), 2);

    // sorted by id: debug.dummy then network.rpc
    REQUIRE_EQ(plan[0].id, "debug.dummy");
    REQUIRE(plan[0].from.has_value());
    REQUIRE_EQ(*plan[0].from, "1.0.0");
    REQUIRE_EQ(plan[0].to, "9.9.9");
    REQUIRE_EQ(plan[0].reason, "version_mismatch");

    REQUIRE_EQ(plan[1].id, "network.rpc");
    REQUIRE_FALSE(plan[1].from.has_value());
    REQUIRE_EQ(plan[1].reason, "prefer_present");
}

TEST_CASE("test_plugin_local_inventory/plan_missing_override") {
    auto dir = temp_dir("ds_plugin_inv_plan_missing");
    // empty dir

    PluginPinConfig cfg = defaults();
    cfg.pins["core.vm"] = PinEntry{"0.2.0", "override"};

    auto inv = scan_local_inventory(dir);
    auto plan = build_plan_actions(cfg, inv);
    REQUIRE_EQ(plan.size(), 1);
    REQUIRE_EQ(plan[0].id, "core.vm");
    REQUIRE_FALSE(plan[0].from.has_value());
    REQUIRE_EQ(plan[0].to, "0.2.0");
    REQUIRE_EQ(plan[0].reason, "missing");
}

TEST_CASE("test_plugin_local_inventory/status_with_channel_cache") {
    LocalPluginEntry e;
    e.id = "core.vm";
    e.version = "0.1.0";
    e.module = "plugin_core_vm.dll";
    e.has_meta = true;
    e.has_module = true;

    PluginPinConfig cfg = defaults();
    // channel pin (not override) → desired follows channel cache
    cfg.pins["core.vm"] = PinEntry{"0.1.0", "channel"};

    ChannelVersionCache cache;
    cache["core.vm"] = "0.3.0";

    auto rows = build_plugin_status(cfg, {e}, cache);
    REQUIRE_EQ(rows.size(), 1);
    REQUIRE(rows[0].channel_version.has_value());
    REQUIRE_EQ(*rows[0].channel_version, "0.3.0");
    REQUIRE(rows[0].desired_version.has_value());
    REQUIRE_EQ(*rows[0].desired_version, "0.3.0");
    REQUIRE_EQ(rows[0].state, "update_available");
}

TEST_CASE("test_plugin_local_inventory/plugins_dir_from_module_dir") {
    // Already inside plugins/ → do not append again.
    {
        const fs::path mod = fs::path("C:/game/bin64/plugins");
        const auto out = plugins_dir_from_module_dir(mod);
        REQUIRE_EQ(out, mod);
        const bool plugins_leaf = out.filename() == "plugins" || out.filename() == "Plugins";
        REQUIRE(plugins_leaf);
    }
    // Injector-style dir → append plugins.
    {
        const fs::path mod = fs::path("C:/game/bin64");
        const auto out = plugins_dir_from_module_dir(mod);
        REQUIRE_EQ(out, mod / "plugins");
    }
    // Case-insensitive leaf match (Windows).
    {
        const fs::path mod = fs::path("D:/Install/Plugins");
        const auto out = plugins_dir_from_module_dir(mod);
        REQUIRE_EQ(out, mod);
    }
    // Empty → empty.
    {
        REQUIRE(plugins_dir_from_module_dir({}).empty());
    }
    // Relative plugins leaf.
    {
        const fs::path mod = fs::path("plugins");
        REQUIRE_EQ(plugins_dir_from_module_dir(mod), mod);
    }
    // Nested plugins/plugins still ends with plugins → leave as-is (caller already there).
    {
        const fs::path mod = fs::path("/opt/app/plugins");
        REQUIRE_EQ(plugins_dir_from_module_dir(mod), mod);
    }
}


static void write_file(const fs::path &p, const std::string &content) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    out << content;
}

TEST_CASE("test_plugin_local_inventory/cross_tag_pin_unavailable") {
    // Spec: an override pin must exist on the CURRENT channel tag; otherwise the row is
    // pin_unavailable (and apply refuses with "switch channel/tag first").
    auto dir = temp_dir("ds_inv_pin_offtag");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.meta.json",
                   R"({"id":"debug.dummy","version":"1.0.0"})");
    write_pkg_text(dir, "plugin_dummy", "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    cfg.pins["debug.dummy"] = PinEntry{"0.9.0", "override"};
    ChannelVersionCache channel;
    channel["debug.dummy"] = "2.0.0"; // current tag publishes 2.0.0 only

    const auto inv = scan_local_inventory(dir);
    const auto rows = build_plugin_status(cfg, inv, channel);
    REQUIRE_EQ(rows.size(), 1);
    REQUIRE(rows[0].desired_version.has_value());
    REQUIRE_EQ(*rows[0].desired_version, "0.9.0");
    REQUIRE(rows[0].channel_version.has_value());
    REQUIRE_EQ(*rows[0].channel_version, "2.0.0");
    REQUIRE_EQ(rows[0].state, "pin_unavailable");

    // The plan still lists it (so the UI shows the intent) but marked unsatisfiable.
    const auto plan = build_plan_actions(cfg, inv, channel);
    REQUIRE_EQ(plan.size(), 1);
    REQUIRE_EQ(plan[0].to, "0.9.0");
    REQUIRE_EQ(plan[0].reason, "pin_unavailable");

    // Pin equal to the channel version is satisfiable: normal update_available.
    cfg.pins["debug.dummy"] = PinEntry{"2.0.0", "override"};
    const auto rows2 = build_plugin_status(cfg, inv, channel);
    REQUIRE_EQ(rows2[0].state, "update_available");
}

TEST_CASE("test_plugin_local_inventory/flat_module_ignored") {
    // Flat modules are unsupported (the loader ignores them), so they must not show up in
    // the inventory either — only the package copy counts.
    auto dir = temp_dir("ds_inv_flat_ignored");
    write_file(dir / "plugin_dummy.dll", "FLAT");
    write_file(dir / "plugin_dummy.meta.json", R"({"id":"debug.dummy","version":"1.0.0"})");
    write_file(dir / "plugin_dummy" / "plugin_dummy.dll", "PKG");
    write_file(dir / "plugin_dummy" / "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"2.0.0"})");

    const auto inv = scan_local_inventory(dir);
    REQUIRE_EQ(inv.size(), 1);
    REQUIRE_EQ(inv[0].id, "debug.dummy");
    REQUIRE_EQ(inv[0].path, dir / "plugin_dummy" / "plugin_dummy.dll");
    REQUIRE(inv[0].version.has_value());
    REQUIRE_EQ(*inv[0].version, "2.0.0");

    // Flat-only tree: no plugins at all.
    auto flat_only = temp_dir("ds_inv_flat_only");
    write_file(flat_only / "plugin_dummy.dll", "FLAT");
    REQUIRE(scan_local_inventory(flat_only).empty());
}
