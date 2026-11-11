// test_config_view_build — ConfigView SSOT merge (BuildConfigView).
// CF-S4: BuildConfigView(schema, resolved) fills late schema defaults only;
// ResolvedConfig.view is Host SSOT (no GameJitModConfig dual bag for gates).
#include "config/ConfigSchema.hpp"
#include "core/PluginConfigBridge.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"

#include <algorithm>
#include <string>
#include <doctest/doctest.h>

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
        REQUIRE(schema.add(std::move(e)));
    }
    {
        OptionSchemaEntry e;
        e.key = "EnableNetSim";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        REQUIRE(schema.add(std::move(e)));
    }
    {
        OptionSchemaEntry e;
        e.key = "EnableVBPool";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        REQUIRE(schema.add(std::move(e)));
    }
    {
        OptionSchemaEntry e;
        e.key = "AngleBackend";
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("auto");
        e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};
        REQUIRE(schema.add(std::move(e)));
    }
    return schema;
}

// Build a cascade-like resolved view (core + business keys).
static ConfigView make_resolved(std::initializer_list<std::pair<const char *, ConfigValue>> entries = {}) {
    ConfigView view;
    // Core keys always present after cascade (modinfo defaults at minimum).
    view["DisableJITWhenServer"] = ConfigValue::boolean(false);
    view["LuaVmType"] = ConfigValue::string("");
    view["EnabledGenGC"] = ConfigValue::boolean(false);
    for (const auto &p : entries) {
        view[p.first] = p.second;
    }
    return view;
}

TEST_CASE("test_config_view_build/vbpool_true_maps_to_config_key") {
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(true)},
        {"AngleBackend", ConfigValue::string("auto")},
        {"DisableJITWhenServer", ConfigValue::boolean(true)},
    });

    ConfigView view = BuildConfigView(make_production_schema(), resolved);
    auto it = view.find("EnableVBPool");
    REQUIRE_NE(it, view.end());
    REQUIRE(it->second.type == ConfigValueType::Bool);
    REQUIRE(it->second.b == true);
}

TEST_CASE("test_config_view_build/vbpool_false_maps_to_config_key") {
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(false)},
        {"AngleBackend", ConfigValue::string("vulkan")},
        {"DisableJITWhenServer", ConfigValue::boolean(false)},
    });

    ConfigView view = BuildConfigView(make_production_schema(), resolved);
    auto it = view.find("EnableVBPool");
    REQUIRE_NE(it, view.end());
    REQUIRE(it->second.type == ConfigValueType::Bool);
    REQUIRE(it->second.b == false);

    auto angle = view.find("AngleBackend");
    REQUIRE_NE(angle, view.end());
    REQUIRE(angle->second.type == ConfigValueType::String);
    REQUIRE(angle->second.s == "vulkan");

    auto server_disabled = view.find("DisableJITWhenServer");
    REQUIRE_NE(server_disabled, view.end());
    REQUIRE(server_disabled->second.type == ConfigValueType::Bool);
    REQUIRE(server_disabled->second.b == false);

    auto net = view.find("NetworkOpt");
    REQUIRE_NE(net, view.end());
    REQUIRE(net->second.type == ConfigValueType::Bool);
    REQUIRE(net->second.b == true); // late schema default
}

TEST_CASE("test_config_view_build/build_config_view_schema_defaults_and_overlay") {
    ConfigSchemaRegistry schema = make_production_schema();
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(true)}, // overlay over schema default false
        {"AngleBackend", ConfigValue::string("d3d11")},
        {"DisableJITWhenServer", ConfigValue::boolean(true)},
        {"LuaVmType", ConfigValue::string("jit")},
        {"EnabledGenGC", ConfigValue::boolean(true)},
    });

    ConfigView view = BuildConfigView(schema, resolved);

    // Schema defaults for keys cascade did not set.
    REQUIRE_EQ(view.at("NetworkOpt").type, ConfigValueType::Bool);
    REQUIRE_EQ(view.at("NetworkOpt").b, true);
    REQUIRE_EQ(view.at("EnableNetSim").type, ConfigValueType::Bool);
    REQUIRE_EQ(view.at("EnableNetSim").b, false);

    // Cascade-resolved overlays preserved.
    REQUIRE_EQ(view.at("EnableVBPool").b, true);
    REQUIRE_EQ(view.at("AngleBackend").s, "d3d11");

    // Core from resolved.
    REQUIRE_EQ(view.at("DisableJITWhenServer").b, true);
    REQUIRE_EQ(view.at("LuaVmType").s, "jit");
    REQUIRE_EQ(view.at("EnabledGenGC").b, true);
}

TEST_CASE("test_config_view_build/resolved_values_not_overwritten_by_schema_defaults") {
    ConfigSchemaRegistry schema = make_production_schema();
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(false)},
        {"AngleBackend", ConfigValue::string("auto")},
        {"NetworkOpt", ConfigValue::boolean(false)},
        {"EnableNetSim", ConfigValue::boolean(true)},
    });

    ConfigView view = BuildConfigView(schema, resolved);
    // Cascade values win; schema defaults must not clobber.
    REQUIRE_EQ(view.at("EnableVBPool").b, false);
    REQUIRE_EQ(view.at("AngleBackend").s, "auto");
    REQUIRE_EQ(view.at("NetworkOpt").b, false);
    REQUIRE_EQ(view.at("EnableNetSim").b, true);
}

TEST_CASE("test_config_view_build/late_schema_defaults_for_missing_keys") {
    ConfigSchemaRegistry schema = make_production_schema();
    ConfigView resolved = make_resolved(); // no business keys

    ConfigView view = BuildConfigView(schema, resolved);

    auto it = view.find("EnableNetSim");
    REQUIRE_NE(it, view.end());
    REQUIRE(it->second.type == ConfigValueType::Bool);
    REQUIRE(it->second.b == false);

    // Empty schema must not invent EnableNetSim or NetworkOpt.
    ConfigSchemaRegistry empty;
    ConfigView legacy = BuildConfigView(empty, resolved);
    REQUIRE_EQ(legacy.find("EnableNetSim"), legacy.end());
    REQUIRE_EQ(legacy.find("NetworkOpt"), legacy.end());
    // Resolved VM keys still present.
    REQUIRE_NE(legacy.find("DisableJITWhenServer"), legacy.end());
}

TEST_CASE("test_config_view_build/network_opt_not_forced_when_schema_has_false") {
    ConfigSchemaRegistry schema;
    {
        OptionSchemaEntry e;
        e.key = "NetworkOpt";
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(false);
        REQUIRE(schema.add(std::move(e)));
    }
    ConfigView resolved = make_resolved();
    ConfigView view = BuildConfigView(schema, resolved);
    REQUIRE_EQ(view.at("NetworkOpt").b, false);
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

TEST_CASE("test_config_view_build/empty_registry_resolve_after_bridge_is_noop") {
    ConfigView resolved = make_resolved({
        {"EnableVBPool", ConfigValue::boolean(true)},
        {"AngleBackend", ConfigValue::string("d3d11")},
        {"DisableJITWhenServer", ConfigValue::boolean(true)},
    });
    ConfigView view = BuildConfigView(make_production_schema(), resolved);

    PluginHost host;
    PluginContext ctx;
    ctx.is_client = true;
    auto rr = host.resolve(view, ctx);
    REQUIRE(rr.enabled.empty());
    REQUIRE(rr.failed.empty());
    REQUIRE(rr.disabled.empty());

    auto lr = host.load_phase(PluginPhase::EarlyNative);
    REQUIRE(lr.ok);
    REQUIRE(lr.loaded_order.empty());
    REQUIRE(host.loaded_order(PluginPhase::EarlyNative).empty());
}

TEST_CASE("test_config_view_build/network_rpc_standin_from_bridge_default") {
    ConfigView resolved = make_resolved();
    ConfigView view = BuildConfigView(make_production_schema(), resolved);
    REQUIRE_EQ(view.at("NetworkOpt").type, ConfigValueType::Bool);
    REQUIRE_EQ(view.at("NetworkOpt").b, true);

    NetworkRpcStandIn standin;
    PluginHost host;
    host.register_plugin(&standin);
    PluginContext ctx;
    ctx.is_client = true;
    auto rr = host.resolve(view, ctx);
    REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "network.rpc"), rr.enabled.end());
    REQUIRE(rr.failed.empty());

    auto lr = host.load_phase(PluginPhase::EarlyNative);
    REQUIRE(lr.ok);
    REQUIRE_EQ(lr.loaded_order.size(), 1);
    REQUIRE_EQ(lr.loaded_order[0], "network.rpc");
    REQUIRE_EQ(standin.load_count, 1);
    REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Loaded);
}

TEST_CASE("test_config_view_build/network_rpc_standin_disabled_when_off") {
    NetworkRpcStandIn standin;
    PluginHost host;
    host.register_plugin(&standin);

    ConfigView view;
    view["NetworkOpt"] = ConfigValue::boolean(false);
    PluginContext ctx;
    auto rr = host.resolve(view, ctx);
    REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "network.rpc"), rr.disabled.end());

    auto lr = host.load_phase(PluginPhase::EarlyNative);
    REQUIRE(lr.ok);
    REQUIRE(lr.loaded_order.empty());
    REQUIRE_EQ(standin.load_count, 0);
    REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Disabled);
}

TEST_CASE("test_config_view_build/network_sim_enable_matrix") {
    // EnableNetSim false (schema default) → network.sim disabled
    {
        ConfigView resolved = make_resolved();
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        REQUIRE_EQ(view.at("EnableNetSim").b, false);

        NetworkSimStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        auto rr = host.resolve(view, ctx);
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "network.sim"), rr.disabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE(lr.loaded_order.empty());
        REQUIRE_EQ(standin.load_count, 0);
        REQUIRE_EQ(host.status("network.sim"), PluginStatus::Disabled);
    }

    // EnableNetSim true (cascade overlay / save) → network.sim enabled + load
    {
        ConfigView resolved = make_resolved({
            {"EnableNetSim", ConfigValue::boolean(true)},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        REQUIRE_EQ(view.at("EnableNetSim").b, true);

        NetworkSimStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        auto rr = host.resolve(view, ctx);
        REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "network.sim"), rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(lr.loaded_order.size(), 1);
        REQUIRE_EQ(lr.loaded_order[0], "network.sim");
        REQUIRE_EQ(standin.load_count, 1);
        REQUIRE_EQ(host.status("network.sim"), PluginStatus::Loaded);
    }

    // NetworkOpt false → network.rpc disabled (paired gate matrix row)
    {
        ConfigView resolved = make_resolved({
            {"NetworkOpt", ConfigValue::boolean(false)},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        REQUIRE_EQ(view.at("NetworkOpt").b, false);

        NetworkRpcStandIn rpc;
        NetworkSimStandIn sim;
        PluginHost host;
        host.register_plugin(&rpc);
        host.register_plugin(&sim);
        PluginContext ctx;
        auto rr = host.resolve(view, ctx);
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "network.rpc"), rr.disabled.end());
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "network.sim"), rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        REQUIRE_EQ(rpc.load_count, 0);
        REQUIRE_EQ(sim.load_count, 0);
    }
}

TEST_CASE("test_config_view_build/render_vbpool_from_bridge_enable_matrix") {
    // EnableVBPool true → EarlyNative load
    {
        ConfigView resolved = make_resolved({
            {"EnableVBPool", ConfigValue::boolean(true)},
            {"AngleBackend", ConfigValue::string("auto")},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        REQUIRE_EQ(view.at("EnableVBPool").b, true);

        RenderVbpoolStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        ctx.is_client = true;
        auto rr = host.resolve(view, ctx);
        REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "render.vbpool"), rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(standin.load_count, 1);
        REQUIRE_EQ(host.status("render.vbpool"), PluginStatus::Loaded);
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
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "render.vbpool"), rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        REQUIRE_EQ(standin.load_count, 0);
        REQUIRE_EQ(host.status("render.vbpool"), PluginStatus::Disabled);
    }
}

TEST_CASE("test_config_view_build/render_angle_backend_reaches_plugin") {
    // AngleBackend is a parameter: plugin AlwaysOn on client; backend string reaches load.
    const char *backends[] = {"auto", "vulkan", "d3d11", "d3d9"};
    for (const char *backend : backends) {
        ConfigView resolved = make_resolved({
            {"EnableVBPool", ConfigValue::boolean(false)},
            {"AngleBackend", ConfigValue::string(backend)},
        });
        ConfigView view = BuildConfigView(make_production_schema(), resolved);
        REQUIRE_EQ(view.at("AngleBackend").s, backend);

        RenderAngleStandIn standin;
        PluginHost host;
        host.register_plugin(&standin);
        PluginContext ctx;
        ctx.is_client = true;
        auto rr = host.resolve(view, ctx);
        REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "render.angle"), rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(standin.load_count, 1);
        REQUIRE_EQ(standin.last_backend, backend);
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
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "render.angle"), rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        REQUIRE_EQ(standin.load_count, 0);
    }
}
