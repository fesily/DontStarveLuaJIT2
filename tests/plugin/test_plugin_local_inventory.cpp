#include "plugins/plugin_manager/PluginLocalInventory.hpp"
#include "plugins/plugin_manager/PluginPinConfig.hpp"

#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
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

static void write_text(const fs::path &p, const std::string &body) {
    std::ofstream out(p, std::ios::binary);
    assert(out.is_open());
    out << body;
    assert(out);
}

static void test_scan_meta_and_module() {
    auto dir = temp_dir("ds_plugin_inv_meta");
    write_text(dir / "plugin_dummy.meta.json",
               R"({
  "id": "debug.dummy",
  "version": "1.2.3",
  "sha256": "abc123",
  "module": "plugin_dummy.dll"
}
)");
    // Fake module binary (content irrelevant for inventory).
    write_text(dir / "plugin_dummy.dll", "MZ-fake");

    auto inv = scan_local_inventory(dir);
    assert(inv.size() == 1);
    assert(inv[0].id == "debug.dummy");
    assert(inv[0].version.has_value());
    assert(*inv[0].version == "1.2.3");
    assert(inv[0].sha256.has_value());
    assert(*inv[0].sha256 == "abc123");
    assert(inv[0].module == "plugin_dummy.dll");
    assert(inv[0].has_meta);
    assert(inv[0].has_module);
    printf("PASS: scan_meta_and_module\n");
}

static void test_module_without_meta_version_unknown() {
    auto dir = temp_dir("ds_plugin_inv_nometa");
    write_text(dir / "plugin_core_vm.dll", "MZ-fake");

    auto inv = scan_local_inventory(dir);
    assert(inv.size() == 1);
    assert(inv[0].id == "core.vm"); // mapped stem
    assert(!inv[0].version.has_value());
    assert(inv[0].has_module);
    assert(!inv[0].has_meta);
    printf("PASS: module_without_meta_version_unknown\n");
}

static void test_missing_dir_empty() {
    auto inv = scan_local_inventory(fs::temp_directory_path() / "ds_plugin_inv_missing_xyz");
    assert(inv.empty());
    printf("PASS: missing_dir_empty\n");
}

static void test_status_override_update_available() {
    auto dir = temp_dir("ds_plugin_inv_status");
    write_text(dir / "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"1.0.0","sha256":"x","module":"plugin_dummy.dll"})");
    write_text(dir / "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    cfg.pins["debug.dummy"] = PinEntry{"2.0.0", "override"};

    auto inv = scan_local_inventory(dir);
    auto rows = build_plugin_status(cfg, inv);
    assert(rows.size() == 1);
    assert(rows[0].id == "debug.dummy");
    assert(rows[0].local_version && *rows[0].local_version == "1.0.0");
    assert(rows[0].desired_version && *rows[0].desired_version == "2.0.0");
    assert(rows[0].pin_source && *rows[0].pin_source == "override");
    assert(rows[0].state == "update_available");
    assert(!rows[0].channel_version.has_value());
    printf("PASS: status_override_update_available\n");
}

static void test_status_local_only_ok() {
    auto dir = temp_dir("ds_plugin_inv_ok");
    write_text(dir / "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"1.0.0","module":"plugin_dummy.dll"})");
    write_text(dir / "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    auto inv = scan_local_inventory(dir);
    auto rows = build_plugin_status(cfg, inv);
    assert(rows.size() == 1);
    assert(rows[0].state == "ok");
    assert(!rows[0].desired_version.has_value());
    printf("PASS: status_local_only_ok\n");
}

static void test_plan_mismatch_and_prefer_present() {
    auto dir = temp_dir("ds_plugin_inv_plan");
    write_text(dir / "plugin_dummy.meta.json",
               R"({"id":"debug.dummy","version":"1.0.0","module":"plugin_dummy.dll"})");
    write_text(dir / "plugin_dummy.dll", "MZ");

    PluginPinConfig cfg = defaults();
    cfg.pins["debug.dummy"] = PinEntry{"9.9.9", "override"};
    cfg.prefer_present.push_back("network.rpc"); // missing soft preference

    auto inv = scan_local_inventory(dir);
    auto plan = build_plan_actions(cfg, inv);
    assert(plan.size() == 2);

    // sorted by id: debug.dummy then network.rpc
    assert(plan[0].id == "debug.dummy");
    assert(plan[0].from && *plan[0].from == "1.0.0");
    assert(plan[0].to == "9.9.9");
    assert(plan[0].reason == "version_mismatch");

    assert(plan[1].id == "network.rpc");
    assert(!plan[1].from.has_value());
    assert(plan[1].reason == "prefer_present");
    printf("PASS: plan_mismatch_and_prefer_present\n");
}

static void test_plan_missing_override() {
    auto dir = temp_dir("ds_plugin_inv_plan_missing");
    // empty dir

    PluginPinConfig cfg = defaults();
    cfg.pins["core.vm"] = PinEntry{"0.2.0", "override"};

    auto inv = scan_local_inventory(dir);
    auto plan = build_plan_actions(cfg, inv);
    assert(plan.size() == 1);
    assert(plan[0].id == "core.vm");
    assert(!plan[0].from.has_value());
    assert(plan[0].to == "0.2.0");
    assert(plan[0].reason == "missing");
    printf("PASS: plan_missing_override\n");
}

static void test_status_with_channel_cache() {
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
    assert(rows.size() == 1);
    assert(rows[0].channel_version && *rows[0].channel_version == "0.3.0");
    assert(rows[0].desired_version && *rows[0].desired_version == "0.3.0");
    assert(rows[0].state == "update_available");
    printf("PASS: status_with_channel_cache\n");
}

static void test_plugins_dir_from_module_dir() {
    // Already inside plugins/ → do not append again.
    {
        const fs::path mod = fs::path("C:/game/bin64/plugins");
        const auto out = plugins_dir_from_module_dir(mod);
        assert(out == mod);
        assert(out.filename() == "plugins" || out.filename() == "Plugins");
    }
    // Injector-style dir → append plugins.
    {
        const fs::path mod = fs::path("C:/game/bin64");
        const auto out = plugins_dir_from_module_dir(mod);
        assert(out == mod / "plugins");
    }
    // Case-insensitive leaf match (Windows).
    {
        const fs::path mod = fs::path("D:/Install/Plugins");
        const auto out = plugins_dir_from_module_dir(mod);
        assert(out == mod);
    }
    // Empty → empty.
    {
        assert(plugins_dir_from_module_dir({}).empty());
    }
    // Relative plugins leaf.
    {
        const fs::path mod = fs::path("plugins");
        assert(plugins_dir_from_module_dir(mod) == mod);
    }
    // Nested plugins/plugins still ends with plugins → leave as-is (caller already there).
    {
        const fs::path mod = fs::path("/opt/app/plugins");
        assert(plugins_dir_from_module_dir(mod) == mod);
    }
    printf("PASS: plugins_dir_from_module_dir\n");
}


int main() {
    test_scan_meta_and_module();
    test_module_without_meta_version_unknown();
    test_missing_dir_empty();
    test_status_override_update_available();
    test_status_local_only_ok();
    test_plan_mismatch_and_prefer_present();
    test_plan_missing_override();
    test_status_with_channel_cache();
    test_plugins_dir_from_module_dir();
    printf("ALL PASS plugin_local_inventory\n");
    return 0;
}
