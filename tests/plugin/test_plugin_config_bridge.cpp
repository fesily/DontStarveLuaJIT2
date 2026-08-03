#include "core/PluginConfigBridge.hpp"
#include "core/PluginHost.hpp"
#include "core/RegisterBuiltinPlugins.hpp"

#include <cassert>
#include <cstdio>
#include <string>

using namespace ds::plugin;

static void test_vbpool_true_maps_to_config_key() {
    GameJitModConfig cfg{};
    cfg.EnableVBPool = true;
    cfg.AngleBackend = "auto";
    cfg.AlwaysEnableMod = true;

    ConfigView view = FromGameJitModConfig(cfg);
    auto it = view.find("EnableVBPool");
    assert(it != view.end());
    assert(it->second.type == ConfigValueType::Bool);
    assert(it->second.b == true);
    printf("PASS: vbpool_true_maps_to_config_key\n");
}

static void test_vbpool_false_maps_to_config_key() {
    GameJitModConfig cfg{};
    cfg.EnableVBPool = false;
    cfg.AngleBackend = "vulkan";
    cfg.AlwaysEnableMod = false;

    ConfigView view = FromGameJitModConfig(cfg);
    auto it = view.find("EnableVBPool");
    assert(it != view.end());
    assert(it->second.type == ConfigValueType::Bool);
    assert(it->second.b == false);

    auto angle = view.find("AngleBackend");
    assert(angle != view.end());
    assert(angle->second.type == ConfigValueType::String);
    assert(angle->second.s == "vulkan");

    auto always = view.find("AlwaysEnableMod");
    assert(always != view.end());
    assert(always->second.type == ConfigValueType::Bool);
    assert(always->second.b == false);

    auto net = view.find("NetworkOpt");
    assert(net != view.end());
    assert(net->second.type == ConfigValueType::Bool);
    assert(net->second.b == true); // modinfo default until native cascade owns it
    printf("PASS: vbpool_false_and_early_keys\n");
}

static void test_empty_registry_resolve_after_bridge_is_noop() {
    GameJitModConfig cfg{};
    cfg.EnableVBPool = true;
    cfg.AngleBackend = "d3d11";
    cfg.AlwaysEnableMod = true;

    ConfigView view = FromGameJitModConfig(cfg);

    PluginHost host;
    RegisterBuiltinPlugins(host); // M0/M1: empty registry
    PluginContext ctx;
    ctx.is_client = true;
    auto rr = host.resolve(view, ctx);
    assert(rr.enabled.empty());
    assert(rr.failed.empty());
    assert(rr.disabled.empty());

    auto lr = host.load_phase(PluginPhase::EarlyNative);
    assert(lr.ok);
    assert(lr.loaded_order.empty());
    assert(host.loaded_order(PluginPhase::EarlyNative).empty());
    printf("PASS: empty_registry_resolve_after_bridge_noop\n");
}

int main() {
    test_vbpool_true_maps_to_config_key();
    test_vbpool_false_maps_to_config_key();
    test_empty_registry_resolve_after_bridge_is_noop();
    printf("All plugin config bridge tests passed!\n");
    return 0;
}
