// test_config_view_build — ConfigView SSOT merge (BuildConfigView).
// CF-S4: BuildConfigView(schema, resolved) fills late schema defaults only;
// ResolvedConfig.view is Host SSOT (no GameJitModConfig dual bag for gates).
#include "config/ConfigSchema.hpp"
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

// Production-like schema defaults (matches plugins after C-S1).
static ConfigSchemaRegistry make_production_schema() {
    ConfigSchemaRegistry schema;
    {
        OptionSchemaEntry e;
        e.key = "NetworkOpt";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(true);
        assert(schema.add(std::move(e)));
    }
    {
        OptionSchemaEntry e;
        e.key = "EnableNetSim";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        assert(schema.add(std::move(e)));
    }
    {
        OptionSchemaEntry e;
        e.key = "EnableVBPool";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        assert(schema.add(std::move(e)));
    }
    {
        OptionSchemaEntry e;
        e.key = "AngleBackend";
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("auto");
        e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};
        assert(schema.add(std::move(e)));
    }
    return schema;
}

// Build a cascade-like resolved view (core + business keys).
static ConfigView make_resolved(std::initializer_list<std::pair<const char *, ConfigValue>> entries = {}) {
    ConfigView view;
    // Core keys always present after cascade (modinfo defaults at minimum).
    view["AlwaysEnableMod"] = ConfigValue::boolean(false);
    view["DisableJITWhenServer"] = ConfigValue::boolean(false);
    view["LuaVmType"] = ConfigValue::string("");
    view["EnabledGenGC"] = ConfigValue::boolean(false);
    for (const auto &p : entries) {
        view[p.first] = p.second;
    }
    return view;
}

static void test_vbpool_true_maps_to_config_key() {
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(true)},
        {"AngleBackend", ConfigValue::string("auto")},
        {"AlwaysEnableMod", ConfigValue::boolean(true)},
    });

    ConfigView view = BuildConfigView(make_production_schema(), resolved);
    auto it = view.find("EnableVBPool");
    assert(it != view.end());
    assert(it->second.type == ConfigValueType::Bool);
    assert(it->second.b == true);
    printf("PASS: vbpool_true_maps_to_config_key\n");
}

static void test_vbpool_false_maps_to_config_key() {
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(false)},
        {"AngleBackend", ConfigValue::string("vulkan")},
        {"AlwaysEnableMod", ConfigValue::boolean(false)},
    });

    ConfigView view = BuildConfigView(make_production_schema(), resolved);
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
    assert(net->second.b == true); // late schema default
    printf("PASS: vbpool_false_and_early_keys\n");
}

static void test_build_config_view_schema_defaults_and_overlay() {
    ConfigSchemaRegistry schema = make_production_schema();
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(true)}, // overlay over schema default false
        {"AngleBackend", ConfigValue::string("d3d11")},
        {"AlwaysEnableMod", ConfigValue::boolean(true)},
        {"DisableJITWhenServer", ConfigValue::boolean(true)},
        {"LuaVmType", ConfigValue::string("jit")},
        {"EnabledGenGC", ConfigValue::boolean(true)},
    });

    ConfigView view = BuildConfigView(schema, resolved);

    // Schema defaults for keys cascade did not set.
    assert(view.at("NetworkOpt").type == ConfigValueType::Bool);
    assert(view.at("NetworkOpt").b == true);
    assert(view.at("EnableNetSim").type == ConfigValueType::Bool);
    assert(view.at("EnableNetSim").b == false);

    // Cascade-resolved overlays preserved.
    assert(view.at("EnableVBPool").b == true);
    assert(view.at("AngleBackend").s == "d3d11");

    // Core from resolved.
    assert(view.at("AlwaysEnableMod").b == true);
    assert(view.at("DisableJITWhenServer").b == true);
    assert(view.at("LuaVmType").s == "jit");
    assert(view.at("EnabledGenGC").b == true);

    printf("PASS: build_config_view_schema_defaults_and_overlay\n");
}

static void test_resolved_values_not_overwritten_by_schema_defaults() {
    ConfigSchemaRegistry schema = make_production_schema();
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(false)},
        {"AngleBackend", ConfigValue::string("auto")},
        {"NetworkOpt", ConfigValue::boolean(false)},
        {"EnableNetSim", ConfigValue::boolean(true)},
    });

    ConfigView view = BuildConfigView(schema, resolved);
    // Cascade values win; schema defaults must not clobber.
    assert(view.at("EnableVBPool").b == false);
    assert(view.at("AngleBackend").s == "auto");
    assert(view.at("NetworkOpt").b == false);
    assert(view.at("EnableNetSim").b == true);
    printf("PASS: resolved_values_not_overwritten_by_schema_defaults\n");
}

static void test_late_schema_defaults_for_missing_keys() {
    ConfigSchemaRegistry schema = make_production_schema();
    ConfigView resolved = make_resolved(); // no business keys

    ConfigView view = BuildConfigView(schema, resolved);

    auto it = view.find("EnableNetSim");
    assert(it != view.end());
    assert(it->second.type == ConfigValueType::Bool);
    assert(it->second.b == false);

    // Empty schema must not invent EnableNetSim or NetworkOpt.
    ConfigSchemaRegistry empty;
    ConfigView legacy = BuildConfigView(empty, resolved);
    assert(legacy.find("EnableNetSim") == legacy.end());
    assert(legacy.find("NetworkOpt") == legacy.end());
    // Core keys from resolved still present.
    assert(legacy.find("AlwaysEnableMod") != legacy.end());

    printf("PASS: late_schema_defaults_for_missing_keys\n");
}

static void test_network_opt_not_forced_when_schema_has_false() {
    ConfigSchemaRegistry schema;
    {
        OptionSchemaEntry e;
        e.key = "NetworkOpt";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        assert(schema.add(std::move(e)));
    }
    ConfigView resolved = make_resolved();
    ConfigView view = BuildConfigView(schema, resolved);
    assert(view.at("NetworkOpt").b == false);
    printf("PASS: network_opt_not_forced_when_schema_has_false\n");
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

struct NetworkSimStandIn final : IPlugin {
    PluginManifest man{};
    int load_count = 0;
    NetworkSimStandIn() {
        man.id = "network.sim";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.priority = 60;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableNetSim"};
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
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(true)},
        {"AngleBackend", ConfigValue::string("d3d11")},
        {"AlwaysEnableMod", ConfigValue::boolean(true)},
    });
    ConfigView view = BuildConfigView(make_production_schema(), resolved);

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
    ConfigView resolved = make_resolved();
    ConfigView view = BuildConfigView(make_production_schema(), resolved);
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

static void test_network_sim_enable_matrix() {
    // EnableNetSim false (schema default) → network.sim disabled
    {
        ConfigView resolved = make_resolved();
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        assert(view.at("EnableNetSim").b == false);

        NetworkSimStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.disabled.begin(), rr.disabled.end(), "network.sim") != rr.disabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        assert(lr.ok);
        assert(lr.loaded_order.empty());
        assert(standin.load_count == 0);
        assert(host.status("network.sim") == PluginStatus::Disabled);
    }

    // EnableNetSim true (cascade overlay / save) → network.sim enabled + load
    {
        ConfigView resolved = make_resolved({
            {"EnableNetSim", ConfigValue::boolean(true)},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        assert(view.at("EnableNetSim").b == true);

        NetworkSimStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.enabled.begin(), rr.enabled.end(), "network.sim") != rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        assert(lr.ok);
        assert(lr.loaded_order.size() == 1);
        assert(lr.loaded_order[0] == "network.sim");
        assert(standin.load_count == 1);
        assert(host.status("network.sim") == PluginStatus::Loaded);
    }

    // NetworkOpt false → network.rpc disabled (paired gate matrix row)
    {
        ConfigView resolved = make_resolved({
            {"NetworkOpt", ConfigValue::boolean(false)},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        assert(view.at("NetworkOpt").b == false);

        NetworkRpcStandIn rpc;
        NetworkSimStandIn sim;
        PluginHost host;
        host.register_plugin(&rpc);
        host.register_plugin(&sim);
        PluginContext ctx;
        auto rr = host.resolve(view, ctx);
        assert(std::find(rr.disabled.begin(), rr.disabled.end(), "network.rpc") != rr.disabled.end());
        assert(std::find(rr.disabled.begin(), rr.disabled.end(), "network.sim") != rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        assert(rpc.load_count == 0);
        assert(sim.load_count == 0);
    }

    printf("PASS: network_sim_enable_matrix\n");
}

static void test_render_vbpool_from_bridge_enable_matrix() {
    // EnableVBPool true → EarlyNative load
    {
        ConfigView resolved = make_resolved({
            {"EnableVBPool", ConfigValue::boolean(true)},
            {"AngleBackend", ConfigValue::string("auto")},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
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
        ConfigView resolved = make_resolved({
            {"EnableVBPool", ConfigValue::boolean(false)},
            {"AngleBackend", ConfigValue::string("auto")},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);

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
        ConfigView resolved = make_resolved({
            {"EnableVBPool", ConfigValue::boolean(false)},
            {"AngleBackend", ConfigValue::string(backend)},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
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
        ConfigView resolved = make_resolved({
            {"AngleBackend", ConfigValue::string("vulkan")},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
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
    test_build_config_view_schema_defaults_and_overlay();
    test_resolved_values_not_overwritten_by_schema_defaults();
    test_late_schema_defaults_for_missing_keys();
    test_network_opt_not_forced_when_schema_has_false();
    test_empty_registry_resolve_after_bridge_is_noop();
    test_network_rpc_standin_from_bridge_default();
    test_network_rpc_standin_disabled_when_off();
    test_network_sim_enable_matrix();
    test_render_vbpool_from_bridge_enable_matrix();
    test_render_angle_backend_reaches_plugin();
    printf("All config view build tests passed!\n");
    return 0;
}
