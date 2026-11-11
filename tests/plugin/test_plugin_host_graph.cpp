#include "core/PluginHost.hpp"
#include "core/PluginServices.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <vector>
#include <doctest/doctest.h>
using namespace ds::plugin;

namespace {

struct FakePlugin : IPlugin {
    PluginManifest man{};
    bool allow = true;
    int load_count = 0;
    int unload_count = 0;
    bool throw_on_load = false;
    std::string throw_msg = "boom";

    const PluginManifest &manifest() const override { return man; }
    bool can_load(const PluginContext &) const override { return allow; }
    void load(PluginContext &) override {
        if (throw_on_load) {
            throw std::runtime_error(throw_msg);
        }
        ++load_count;
    }
    void unload(PluginContext &) override { ++unload_count; }
};

OptionRule opt_all(std::vector<std::string> keys) {
    OptionRule r;
    r.kind = OptionRuleKind::AllOf;
    r.keys = std::move(keys);
    return r;
}

OptionRule always() {
    OptionRule r;
    r.kind = OptionRuleKind::AlwaysOn;
    return r;
}

ConfigView cfg_true(std::initializer_list<const char *> keys) {
    ConfigView c;
    for (const char *k : keys) {
        c[k] = ConfigValue::boolean(true);
    }
    return c;
}

void enable_all_true(PluginHost &host, FakePlugin &p, const char *opt = "A") {
    p.man.options = opt_all({opt});
    (void) host;
}

int load_count_of(const FakePlugin &p) { return p.load_count; }

} // namespace

TEST_CASE("test_plugin_host_graph/empty_registry") {
    PluginHost host;
    ConfigView cfg;
    PluginContext ctx;
    host.resolve(cfg, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE(lr.loaded_order.empty());
    REQUIRE(lr.ok);
}

TEST_CASE("test_plugin_host_graph/topo_linear") {
    FakePlugin b, a;
    b.man.id = "B";
    b.man.priority = 10;
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = always();
    a.man.id = "A";
    a.man.priority = 10;
    a.man.phases = PluginPhase::AfterModMain;
    a.man.depends = {"B"};
    a.man.options = always();

    PluginHost host;
    host.register_plugin(&b);
    host.register_plugin(&a);
    PluginContext ctx;
    host.resolve(ConfigView{}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(lr.loaded_order.size(), 2);
    REQUIRE_EQ(lr.loaded_order[0], "B");
    REQUIRE_EQ(lr.loaded_order[1], "A");
    REQUIRE_EQ(b.load_count, 1);
    REQUIRE_EQ(a.load_count, 1);
    REQUIRE_EQ(host.status("A"), PluginStatus::Loaded);
    REQUIRE_EQ(host.status("B"), PluginStatus::Loaded);
}

TEST_CASE("test_plugin_host_graph/topo_diamond") {
    FakePlugin d, b, c, a;
    d.man.id = "D";
    d.man.phases = PluginPhase::AfterModMain;
    d.man.options = always();
    d.man.priority = 1;
    b.man.id = "B";
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = always();
    b.man.depends = {"D"};
    b.man.priority = 2;
    c.man.id = "C";
    c.man.phases = PluginPhase::AfterModMain;
    c.man.options = always();
    c.man.depends = {"D"};
    c.man.priority = 3;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.depends = {"B", "C"};
    a.man.priority = 4;

    PluginHost host;
    host.register_plugin(&a);
    host.register_plugin(&b);
    host.register_plugin(&c);
    host.register_plugin(&d);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(lr.loaded_order.size(), 4);
    auto pos = [&](const char *id) {
        auto it = std::find(lr.loaded_order.begin(), lr.loaded_order.end(), id);
        REQUIRE_NE(it, lr.loaded_order.end());
        return static_cast<int>(it - lr.loaded_order.begin());
    };
    REQUIRE_LT(pos("D"), pos("B"));
    REQUIRE_LT(pos("D"), pos("C"));
    REQUIRE_LT(pos("B"), pos("A"));
    REQUIRE_LT(pos("C"), pos("A"));
}

TEST_CASE("test_plugin_host_graph/soft_dep_missing") {
    FakePlugin a;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.soft_depends = {"Z"};
    PluginHost host;
    host.register_plugin(&a);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(a.load_count, 1);
    REQUIRE_EQ(host.status("A"), PluginStatus::Loaded);
    REQUIRE_EQ(host.fail_reason("A"), PluginFailReason::None);
}

TEST_CASE("test_plugin_host_graph/soft_dep_present") {
    FakePlugin z, a;
    z.man.id = "Z";
    z.man.phases = PluginPhase::AfterModMain;
    z.man.options = always();
    z.man.priority = 5;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.soft_depends = {"Z"};
    a.man.priority = 10;
    PluginHost host;
    host.register_plugin(&a);
    host.register_plugin(&z);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(lr.loaded_order.size(), 2);
    REQUIRE_EQ(lr.loaded_order[0], "Z");
    REQUIRE_EQ(lr.loaded_order[1], "A");
}

TEST_CASE("test_plugin_host_graph/hard_dep_missing") {
    FakePlugin a;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.depends = {"Z"};
    PluginHost host;
    host.register_plugin(&a);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(a.load_count, 0);
    REQUIRE_EQ(host.status("A"), PluginStatus::Failed);
    REQUIRE_EQ(host.fail_reason("A"), PluginFailReason::MissingHardDep);
}

TEST_CASE("test_plugin_host_graph/conflict_both_enabled") {
    FakePlugin a, b;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.conflicts = {"B"};
    b.man.id = "B";
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = always();
    b.man.conflicts = {"A"};
    PluginHost host;
    host.register_plugin(&a);
    host.register_plugin(&b);
    PluginContext ctx;
    host.resolve({}, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(a.load_count, 0);
    REQUIRE_EQ(b.load_count, 0);
    REQUIRE_EQ(host.status("A"), PluginStatus::Failed);
    REQUIRE_EQ(host.status("B"), PluginStatus::Failed);
    REQUIRE_EQ(host.fail_reason("A"), PluginFailReason::Conflict);
    REQUIRE_EQ(host.fail_reason("B"), PluginFailReason::Conflict);
}

TEST_CASE("test_plugin_host_graph/conflict_one_enabled") {
    FakePlugin a, b;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = opt_all({"enA"});
    a.man.conflicts = {"B"};
    b.man.id = "B";
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = opt_all({"enB"});
    b.man.conflicts = {"A"};
    PluginHost host;
    host.register_plugin(&a);
    host.register_plugin(&b);
    PluginContext ctx;
    ConfigView cfg;
    cfg["enA"] = ConfigValue::boolean(true);
    cfg["enB"] = ConfigValue::boolean(false);
    host.resolve(cfg, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(a.load_count, 1);
    REQUIRE_EQ(b.load_count, 0);
    REQUIRE_EQ(host.status("A"), PluginStatus::Loaded);
    REQUIRE_EQ(host.status("B"), PluginStatus::Disabled);
}

TEST_CASE("test_plugin_host_graph/cycle_three") {
    FakePlugin a, b, c;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.depends = {"B"};
    b.man.id = "B";
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = always();
    b.man.depends = {"C"};
    c.man.id = "C";
    c.man.phases = PluginPhase::AfterModMain;
    c.man.options = always();
    c.man.depends = {"A"};
    PluginHost host;
    host.register_plugin(&a);
    host.register_plugin(&b);
    host.register_plugin(&c);
    PluginContext ctx;
    host.resolve({}, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(a.load_count, 0);
    REQUIRE_EQ(b.load_count, 0);
    REQUIRE_EQ(c.load_count, 0);
    REQUIRE_EQ(host.status("A"), PluginStatus::Failed);
    REQUIRE_EQ(host.status("B"), PluginStatus::Failed);
    REQUIRE_EQ(host.status("C"), PluginStatus::Failed);
    REQUIRE_EQ(host.fail_reason("A"), PluginFailReason::Cycle);
}

TEST_CASE("test_plugin_host_graph/phase_barrier") {
    FakePlugin x, y;
    x.man.id = "X";
    x.man.phases = PluginPhase::EarlyNative;
    x.man.options = always();
    y.man.id = "Y";
    y.man.phases = PluginPhase::AfterModMain;
    y.man.options = always();
    y.man.depends = {"X"};
    PluginHost host;
    host.register_plugin(&x);
    host.register_plugin(&y);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto early = host.load_phase(PluginPhase::EarlyNative);
    REQUIRE_EQ(early.loaded_order.size(), 1);
    REQUIRE_EQ(early.loaded_order[0], "X");
    REQUIRE_EQ(y.load_count, 0);
    auto late = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(late.loaded_order.size(), 1);
    REQUIRE_EQ(late.loaded_order[0], "Y");
    REQUIRE_EQ(y.load_count, 1);
}

TEST_CASE("test_plugin_host_graph/phase_skip_disabled") {
    FakePlugin a;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = opt_all({"on"});
    PluginHost host;
    host.register_plugin(&a);
    PluginContext ctx;
    ConfigView cfg;
    cfg["on"] = ConfigValue::boolean(false);
    host.resolve(cfg, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(a.load_count, 0);
    REQUIRE_EQ(host.status("A"), PluginStatus::Disabled);
}

TEST_CASE("test_plugin_host_graph/load_throw_fails_dependents") {
    FakePlugin b, a, c;
    b.man.id = "B";
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = always();
    b.man.priority = 1;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.depends = {"B"};
    a.man.priority = 2;
    a.throw_on_load = true;
    c.man.id = "C";
    c.man.phases = PluginPhase::AfterModMain;
    c.man.options = always();
    c.man.depends = {"A"};
    c.man.priority = 3;
    PluginHost host;
    host.register_plugin(&b);
    host.register_plugin(&a);
    host.register_plugin(&c);
    PluginContext ctx;
    host.resolve({}, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(b.load_count, 1);
    REQUIRE_EQ(a.load_count, 0);
    REQUIRE_EQ(c.load_count, 0);
    REQUIRE_EQ(host.status("B"), PluginStatus::Loaded);
    REQUIRE_EQ(host.status("A"), PluginStatus::Failed);
    REQUIRE_EQ(host.fail_reason("A"), PluginFailReason::LoadThrew);
    REQUIRE_EQ(host.status("C"), PluginStatus::Failed);
    REQUIRE_EQ(host.fail_reason("C"), PluginFailReason::MissingHardDep);
}

TEST_CASE("test_plugin_host_graph/priority_tiebreak") {
    FakePlugin a, b;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.priority = 10;
    b.man.id = "B";
    b.man.phases = PluginPhase::AfterModMain;
    b.man.options = always();
    b.man.priority = 20;
    PluginHost host;
    host.register_plugin(&b);
    host.register_plugin(&a);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(lr.loaded_order.size(), 2);
    REQUIRE_EQ(lr.loaded_order[0], "A");
    REQUIRE_EQ(lr.loaded_order[1], "B");
}

TEST_CASE("test_plugin_host_graph/profiler_before_hide") {
    FakePlugin profiler, jit;
    profiler.man.id = "debug.profiler";
    profiler.man.phases = PluginPhase::AfterModMain;
    profiler.man.options = always();
    profiler.man.priority = 20;
    jit.man.id = "jit.runtime";
    jit.man.phases = PluginPhase::AfterModMain;
    jit.man.options = always();
    jit.man.priority = 70;
    PluginHost host;
    host.register_plugin(&jit);
    host.register_plugin(&profiler);
    PluginContext ctx;
    host.resolve({}, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_EQ(lr.loaded_order.size(), 2);
    REQUIRE_EQ(lr.loaded_order[0], "debug.profiler");
    REQUIRE_EQ(lr.loaded_order[1], "jit.runtime");
}

TEST_CASE("test_plugin_host_graph/sticky_no_unload") {
    FakePlugin a;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.support_reload = false;
    PluginHost host;
    host.register_plugin(&a);
    PluginContext ctx;
    host.resolve({}, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE_FALSE(host.unload_plugin("A", ctx));
    REQUIRE_EQ(a.unload_count, 0);
    REQUIRE_EQ(host.status("A"), PluginStatus::Loaded);
}

TEST_CASE("test_plugin_host_graph/reload_unload") {
    FakePlugin a;
    a.man.id = "A";
    a.man.phases = PluginPhase::AfterModMain;
    a.man.options = always();
    a.man.support_reload = true;
    PluginHost host;
    host.register_plugin(&a);
    PluginContext ctx;
    host.resolve({}, ctx);
    host.load_phase(PluginPhase::AfterModMain);
    REQUIRE(host.unload_plugin("A", ctx));
    REQUIRE_EQ(a.unload_count, 1);
}

TEST_CASE("test_plugin_host_graph/network_rpc_option_matrix") {
    // L-E: NetworkOpt true/false gates EarlyNative network.rpc.
    FakePlugin rpc;
    rpc.man.id = "network.rpc";
    rpc.man.phases = PluginPhase::EarlyNative;
    rpc.man.priority = 40;
    rpc.man.options = opt_all({"NetworkOpt"});

    {
        PluginHost host;
        host.register_plugin(&rpc);
        PluginContext ctx;
        ConfigView cfg = cfg_true({"NetworkOpt"});
        host.resolve(cfg, ctx);
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(lr.loaded_order.size(), 1);
        REQUIRE_EQ(lr.loaded_order[0], "network.rpc");
        REQUIRE_EQ(rpc.load_count, 1);
        REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Loaded);
    }
    rpc.load_count = 0;
    {
        PluginHost host;
        host.register_plugin(&rpc);
        PluginContext ctx;
        ConfigView cfg;
        cfg["NetworkOpt"] = ConfigValue::boolean(false);
        host.resolve(cfg, ctx);
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE(lr.loaded_order.empty());
        REQUIRE_EQ(rpc.load_count, 0);
        REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Disabled);
    }
}

TEST_CASE("test_plugin_host_graph/network_sim_option_matrix") {
    // C-S4: EnableNetSim true/false gates EarlyNative network.sim.
    FakePlugin sim;
    sim.man.id = "network.sim";
    sim.man.phases = PluginPhase::EarlyNative;
    sim.man.priority = 60;
    sim.man.options = opt_all({"EnableNetSim"});

    // EnableNetSim false → disabled (no load)
    {
        PluginHost host;
        host.register_plugin(&sim);
        PluginContext ctx;
        ConfigView cfg;
        cfg["EnableNetSim"] = ConfigValue::boolean(false);
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "network.sim"), rr.disabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE(lr.loaded_order.empty());
        REQUIRE_EQ(sim.load_count, 0);
        REQUIRE_EQ(host.status("network.sim"), PluginStatus::Disabled);
    }
    sim.load_count = 0;
    // EnableNetSim true → enabled + load
    {
        PluginHost host;
        host.register_plugin(&sim);
        PluginContext ctx;
        ConfigView cfg = cfg_true({"EnableNetSim"});
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "network.sim"), rr.enabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(lr.loaded_order.size(), 1);
        REQUIRE_EQ(lr.loaded_order[0], "network.sim");
        REQUIRE_EQ(sim.load_count, 1);
        REQUIRE_EQ(host.status("network.sim"), PluginStatus::Loaded);
    }
}

TEST_CASE("test_plugin_host_graph/network_entity_hard_dep_on_rpc") {
    // L-E / S9: network.entity cannot enable alone; MissingHardDep when rpc off.
    FakePlugin rpc, entity;
    rpc.man.id = "network.rpc";
    rpc.man.phases = PluginPhase::EarlyNative | PluginPhase::AfterModMain;
    rpc.man.priority = 40;
    rpc.man.options = opt_all({"NetworkOpt"});

    entity.man.id = "network.entity";
    entity.man.phases = PluginPhase::AfterModMain;
    entity.man.priority = 40;
    entity.man.depends = {"network.rpc"};
    entity.man.options = opt_all({"NetworkOptEntity"});

    // Row: entity on, rpc off → entity Failed MissingHardDep
    {
        PluginHost host;
        host.register_plugin(&rpc);
        host.register_plugin(&entity);
        PluginContext ctx;
        ConfigView cfg;
        cfg["NetworkOpt"] = ConfigValue::boolean(false);
        cfg["NetworkOptEntity"] = ConfigValue::boolean(true);
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Disabled);
        REQUIRE_EQ(host.status("network.entity"), PluginStatus::Failed);
        REQUIRE_EQ(host.fail_reason("network.entity"), PluginFailReason::MissingHardDep);
        REQUIRE_NE(std::find(rr.failed.begin(), rr.failed.end(), "network.entity"), rr.failed.end());
        host.load_phase(PluginPhase::EarlyNative);
        host.load_phase(PluginPhase::AfterModMain);
        REQUIRE_EQ(rpc.load_count, 0);
        REQUIRE_EQ(entity.load_count, 0);
    }

    // Row: both on → rpc EarlyNative then entity AfterModMain
    rpc.load_count = 0;
    entity.load_count = 0;
    {
        PluginHost host;
        host.register_plugin(&rpc);
        host.register_plugin(&entity);
        PluginContext ctx;
        ConfigView cfg = cfg_true({"NetworkOpt", "NetworkOptEntity"});
        auto rr = host.resolve(cfg, ctx);
        REQUIRE(rr.failed.empty());
        REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Registered);
        REQUIRE_EQ(host.status("network.entity"), PluginStatus::Registered);

        auto lr_early = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr_early.ok);
        REQUIRE_EQ(lr_early.loaded_order.size(), 1);
        REQUIRE_EQ(lr_early.loaded_order[0], "network.rpc");
        REQUIRE_EQ(rpc.load_count, 1);

        auto lr_late = host.load_phase(PluginPhase::AfterModMain);
        REQUIRE(lr_late.ok);
        REQUIRE_EQ(entity.load_count, 1);
        REQUIRE_EQ(host.status("network.entity"), PluginStatus::Loaded);
        REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Loaded);
        // entity after rpc within AfterModMain when both phases load
        auto pos_rpc = std::find(lr_late.loaded_order.begin(), lr_late.loaded_order.end(), "network.rpc");
        auto pos_ent = std::find(lr_late.loaded_order.begin(), lr_late.loaded_order.end(), "network.entity");
        REQUIRE_NE(pos_ent, lr_late.loaded_order.end());
        if (pos_rpc != lr_late.loaded_order.end()) {
            REQUIRE_LT(pos_rpc, pos_ent);
        }
    }

    // Row: entity off, rpc on → entity Disabled, rpc loads
    rpc.load_count = 0;
    entity.load_count = 0;
    {
        PluginHost host;
        host.register_plugin(&rpc);
        host.register_plugin(&entity);
        PluginContext ctx;
        ConfigView cfg;
        cfg["NetworkOpt"] = ConfigValue::boolean(true);
        cfg["NetworkOptEntity"] = ConfigValue::boolean(false);
        host.resolve(cfg, ctx);
        REQUIRE_EQ(host.status("network.rpc"), PluginStatus::Registered);
        REQUIRE_EQ(host.status("network.entity"), PluginStatus::Disabled);
        host.load_phase(PluginPhase::EarlyNative);
        host.load_phase(PluginPhase::AfterModMain);
        REQUIRE_GE(rpc.load_count, 1);
        REQUIRE_EQ(entity.load_count, 0);
    }
}

TEST_CASE("test_plugin_host_graph/render_vbpool_option_matrix") {
    // L-E: render.vbpool EnableVBPool true/false; Win client gate.
    FakePlugin vb;
    vb.man.id = "render.vbpool";
    vb.man.phases = PluginPhase::EarlyNative;
    vb.man.priority = 20;
    vb.man.options = opt_all({"EnableVBPool"});

    // Row: EnableVBPool true + client → Loaded
    {
        PluginHost host;
        host.register_plugin(&vb);
        PluginContext ctx;
        ctx.is_client = true;
        ConfigView cfg;
        cfg["EnableVBPool"] = ConfigValue::boolean(true);
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "render.vbpool"), rr.enabled.end());
        REQUIRE(rr.failed.empty());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(lr.loaded_order.size(), 1);
        REQUIRE_EQ(lr.loaded_order[0], "render.vbpool");
        REQUIRE_EQ(vb.load_count, 1);
        REQUIRE_EQ(host.status("render.vbpool"), PluginStatus::Loaded);
    }

    // Row: EnableVBPool false → Disabled, no load
    vb.load_count = 0;
    {
        PluginHost host;
        host.register_plugin(&vb);
        PluginContext ctx;
        ctx.is_client = true;
        ConfigView cfg;
        cfg["EnableVBPool"] = ConfigValue::boolean(false);
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "render.vbpool"), rr.disabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE(lr.loaded_order.empty());
        REQUIRE_EQ(vb.load_count, 0);
        REQUIRE_EQ(host.status("render.vbpool"), PluginStatus::Disabled);
    }

    // Row: option true but dedicated (not client) → can_load false → Disabled
    vb.load_count = 0;
    vb.allow = false; // mirrors can_load(is_client==false)
    {
        PluginHost host;
        host.register_plugin(&vb);
        PluginContext ctx;
        ctx.is_client = false;
        ConfigView cfg;
        cfg["EnableVBPool"] = ConfigValue::boolean(true);
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "render.vbpool"), rr.disabled.end());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.loaded_order.empty());
        REQUIRE_EQ(vb.load_count, 0);
    }
    vb.allow = true;
}

TEST_CASE("test_plugin_host_graph/render_angle_backend_parameter_matrix") {
    // L-E: render.angle AlwaysOn on Win client; AngleBackend is a parameter that
    // must reach PluginContext.config for every backend value (auto/vulkan/d3d11/d3d9).
    struct AngleStandIn final : IPlugin {
        PluginManifest man{};
        int load_count = 0;
        std::string last_backend;
        bool allow = true;

        AngleStandIn() {
            man.id = "render.angle";
            man.version = "1.0.0";
            man.phases = PluginPhase::EarlyNative;
            man.priority = 30;
            man.options.kind = OptionRuleKind::AlwaysOn;
        }

        const PluginManifest &manifest() const override { return man; }
        bool can_load(const PluginContext &) const override { return allow; }
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

    const char *backends[] = {"auto", "vulkan", "d3d11", "d3d9"};
    for (const char *backend : backends) {
        AngleStandIn angle;
        PluginHost host;
        host.register_plugin(&angle);
        PluginContext ctx;
        ctx.is_client = true;
        ConfigView cfg;
        cfg["AngleBackend"] = ConfigValue::string(backend);
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.enabled.begin(), rr.enabled.end(), "render.angle"), rr.enabled.end());
        REQUIRE(rr.failed.empty());
        auto lr = host.load_phase(PluginPhase::EarlyNative);
        REQUIRE(lr.ok);
        REQUIRE_EQ(lr.loaded_order.size(), 1);
        REQUIRE_EQ(lr.loaded_order[0], "render.angle");
        REQUIRE_EQ(angle.load_count, 1);
        REQUIRE_EQ(angle.last_backend, backend);
        REQUIRE_EQ(host.status("render.angle"), PluginStatus::Loaded);
    }

    // Non-client gate → Disabled even with AlwaysOn options
    {
        AngleStandIn angle;
        angle.allow = false;
        PluginHost host;
        host.register_plugin(&angle);
        PluginContext ctx;
        ctx.is_client = false;
        ConfigView cfg;
        cfg["AngleBackend"] = ConfigValue::string("vulkan");
        auto rr = host.resolve(cfg, ctx);
        REQUIRE_NE(std::find(rr.disabled.begin(), rr.disabled.end(), "render.angle"), rr.disabled.end());
        host.load_phase(PluginPhase::EarlyNative);
        REQUIRE_EQ(angle.load_count, 0);
    }
}


static int dummy_svc() { return 7; } // GiType::I32

TEST_CASE("test_plugin_host_graph/requires_services_missing_fails") {
    PluginHost host;
    FakePlugin a;
    a.man.id = "need.svc";
    a.man.phases = PluginPhase::EarlyNative;
    a.man.options = always();
    a.man.requires_services = {"svc.missing.xyz"};
    host.register_plugin(&a);
    PluginContext ctx;
    ConfigView cfg;
    auto r = host.resolve(cfg, ctx);
    REQUIRE_NE(std::find(r.failed.begin(), r.failed.end(), "need.svc"), r.failed.end());
    REQUIRE_EQ(host.fail_reason("need.svc"), PluginFailReason::MissingService);
}

TEST_CASE("test_plugin_host_graph/requires_services_present_injects") {
    PluginHost host;
    REQUIRE(host.register_service("svc.dummy", &dummy_svc));
    struct CapturePlugin : FakePlugin {
        void *seen = nullptr;
        void load(PluginContext &c) override {
            auto it = c.services.find("svc.dummy");
            seen = (it == c.services.end()) ? nullptr : it->second;
            FakePlugin::load(c);
        }
    } a;
    a.man.id = "has.svc";
    a.man.phases = PluginPhase::EarlyNative;
    a.man.options = always();
    a.man.requires_services = {"svc.dummy"};
    host.register_plugin(&a);
    PluginContext ctx;
    ConfigView cfg;
    auto r = host.resolve(cfg, ctx);
    REQUIRE_EQ(std::find(r.failed.begin(), r.failed.end(), "has.svc"), r.failed.end());
    REQUIRE_NE(std::find(r.enabled.begin(), r.enabled.end(), "has.svc"), r.enabled.end());
    auto lr = host.load_phase(PluginPhase::EarlyNative);
    REQUIRE(lr.ok);
    REQUIRE(a.seen == reinterpret_cast<void *>(&dummy_svc));
}



TEST_CASE("test_plugin_host_graph/failed_provider_poisons_dependents") {
    // B fails MissingService; A.depends={B} must become MissingHardDep (phase 3c).
    PluginHost host;
    FakePlugin b, a;
    b.man.id = "B";
    b.man.phases = PluginPhase::EarlyNative;
    b.man.options = always();
    b.man.requires_services = {"svc.never.registered"};
    a.man.id = "A";
    a.man.phases = PluginPhase::EarlyNative;
    a.man.options = always();
    a.man.depends = {"B"};
    host.register_plugin(&b);
    host.register_plugin(&a);
    PluginContext ctx;
    ConfigView cfg;
    auto r = host.resolve(cfg, ctx);
    REQUIRE_EQ(host.fail_reason("B"), PluginFailReason::MissingService);
    REQUIRE_EQ(host.fail_reason("A"), PluginFailReason::MissingHardDep);
    REQUIRE_NE(std::find(r.failed.begin(), r.failed.end(), "A"), r.failed.end());
    REQUIRE_NE(std::find(r.failed.begin(), r.failed.end(), "B"), r.failed.end());
}
