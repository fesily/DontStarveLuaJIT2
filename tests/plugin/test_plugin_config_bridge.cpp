#include "core/PluginConfigBridge.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>

using namespace ds::plugin;

// Note: this unit binary intentionally does NOT link RegisterBuiltinPlugins.cpp —
// the real NetworkRpcPlugin calls GameNetWorkHookRpc4 (GameNetwork / Frida).
// Manifest-compatible stand-ins cover the same resolve/load contracts.

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

struct NetworkRpcStandIn final : IPlugin {
    PluginManifest man{};
    int load_count = 0;
    NetworkRpcStandIn() {
        man.id = "network.rpc";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.priority = 40;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"NetworkOpt"};
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &) const override { return true; }
    void load(PluginContext &) override { ++load_count; }
    void unload(PluginContext &) override {}
};

struct RenderVbpoolStandIn final : IPlugin {
    PluginManifest man{};
    int load_count = 0;
    bool client_only = true;
    RenderVbpoolStandIn() {
        man.id = "render.vbpool";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.priority = 20;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableVBPool"};
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &ctx) const override {
        return !client_only || ctx.is_client;
    }
    void load(PluginContext &) override { ++load_count; }
    void unload(PluginContext &) override {}
};

struct RenderAngleStandIn final : IPlugin {
    PluginManifest man{};
    int load_count = 0;
    std::string last_backend;
    bool client_only = true;
    RenderAngleStandIn() {
        man.id = "render.angle";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.priority = 30;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }
    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &ctx) const override {
        return !client_only || ctx.is_client;
    }
    void load(PluginContext &ctx) override {
        ++load_count;
        if (ctx.config) {
            auto it = ctx.config->find("AngleBackend");
            if (it != ctx.config->end() && it->second.type == ConfigValueType::String) {
                last_backend = it->second.s;
            }
        }
    }
    void unload(PluginContext &) override {}
};

static void test_empty_registry_resolve_after_bridge_is_noop() {
    GameJitModConfig cfg{};
    cfg.EnableVBPool = true;
    cfg.AngleBackend = "d3d11";
    cfg.AlwaysEnableMod = true;

    ConfigView view = FromGameJitModConfig(cfg);

    PluginHost host;
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

static void test_network_rpc_standin_from_bridge_default() {
    GameJitModConfig cfg{};
    ConfigView view = FromGameJitModConfig(cfg);
    assert(view.at("NetworkOpt").type == ConfigValueType::Bool);
    assert(view.at("NetworkOpt").b == true);

    NetworkRpcStandIn standin;
    PluginHost host;
    host.register_plugin(&standin);
    PluginContext ctx;
    ctx.is_client = true;
    auto rr = host.resolve(view, ctx);
    assert(std::find(rr.enabled.begin(), rr.enabled.end(), "network.rpc") != rr.enabled.end());
    assert(rr.failed.empty());

    auto lr = host.load_phase(PluginPhase::EarlyNative);
    assert(lr.ok);
    assert(lr.loaded_order.size() == 1);
    assert(lr.loaded_order[0] == "network.rpc");
    assert(standin.load_count == 1);
    assert(host.status("network.rpc") == PluginStatus::Loaded);
    printf("PASS: network_rpc_standin_from_bridge_default\n");
}

static void test_network_rpc_standin_disabled_when_off() {
    NetworkRpcStandIn standin;
    PluginHost host;
    host.register_plugin(&standin);

    ConfigView view;
    view["NetworkOpt"] = ConfigValue::boolean(false);
    PluginContext ctx;
    auto rr = host.resolve(view, ctx);
    assert(std::find(rr.disabled.begin(), rr.disabled.end(), "network.rpc") != rr.disabled.end());

    auto lr = host.load_phase(PluginPhase::EarlyNative);
    assert(lr.ok);
    assert(lr.loaded_order.empty());
    assert(standin.load_count == 0);
    assert(host.status("network.rpc") == PluginStatus::Disabled);
    printf("PASS: network_rpc_standin_disabled_when_off\n");
}

static void test_render_vbpool_from_bridge_enable_matrix() {
    // EnableVBPool true → EarlyNative load
    {
        GameJitModConfig cfg{};
        cfg.EnableVBPool = true;
        cfg.AngleBackend = "auto";
        ConfigView view = FromGameJitModConfig(cfg);
        assert(view.at("EnableVBPool").b == true);

        RenderVbpoolStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        ctx.is_client = true;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.enabled.begin(), rr.enabled.end(), "render.vbpool") != rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        assert(lr.ok);
        assert(standin.load_count == 1);
        assert(host.status("render.vbpool") == PluginStatus::Loaded);
    }

    // EnableVBPool false → Disabled
    {
        GameJitModConfig cfg{};
        cfg.EnableVBPool = false;
        cfg.AngleBackend = "auto";
        ConfigView view = FromGameJitModConfig(cfg);

        RenderVbpoolStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        ctx.is_client = true;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.disabled.begin(), rr.disabled.end(), "render.vbpool") != rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        assert(standin.load_count == 0);
        assert(host.status("render.vbpool") == PluginStatus::Disabled);
    }

    printf("PASS: render_vbpool_from_bridge_enable_matrix\n");
}

static void test_render_angle_backend_reaches_plugin() {
    // AngleBackend is a parameter: plugin AlwaysOn on client; backend string reaches load.
    const char *backends[] = {"auto", "vulkan", "d3d11", "d3d9"};
    for (const char *backend : backends) {
        GameJitModConfig cfg{};
        cfg.EnableVBPool = false;
        cfg.AngleBackend = backend;
        ConfigView view = FromGameJitModConfig(cfg);
        assert(view.at("AngleBackend").s == backend);

        RenderAngleStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        ctx.is_client = true;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.enabled.begin(), rr.enabled.end(), "render.angle") != rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        assert(lr.ok);
        assert(standin.load_count == 1);
        assert(standin.last_backend == backend);
    }

    // Server/dedicated: can_load false → Disabled (no ANGLE init on dedicated)
    {
        GameJitModConfig cfg{};
        cfg.AngleBackend = "vulkan";
        ConfigView view = FromGameJitModConfig(cfg);
        RenderAngleStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        ctx.is_client = false;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.disabled.begin(), rr.disabled.end(), "render.angle") != rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        assert(standin.load_count == 0);
    }

    printf("PASS: render_angle_backend_reaches_plugin\n");
}

int main() {
    test_vbpool_true_maps_to_config_key();
    test_vbpool_false_maps_to_config_key();
    test_empty_registry_resolve_after_bridge_is_noop();
    test_network_rpc_standin_from_bridge_default();
    test_network_rpc_standin_disabled_when_off();
    test_render_vbpool_from_bridge_enable_matrix();
    test_render_angle_backend_reaches_plugin();
    printf("All plugin config bridge tests passed!\n");
    return 0;
}
