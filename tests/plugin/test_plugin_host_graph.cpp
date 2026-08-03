#include "core/PluginHost.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>
using namespace ds::plugin;

namespace {

struct FakePlugin final : IPlugin {
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

static void test_empty_registry() {
    PluginHost host;
    ConfigView cfg;
    PluginContext ctx;
    host.resolve(cfg, ctx);
    auto lr = host.load_phase(PluginPhase::AfterModMain);
    assert(lr.loaded_order.empty());
    assert(lr.ok);
    printf("PASS: empty_registry\n");
}

static void test_topo_linear() {
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
    assert(lr.loaded_order.size() == 2);
    assert(lr.loaded_order[0] == "B");
    assert(lr.loaded_order[1] == "A");
    assert(b.load_count == 1 && a.load_count == 1);
    assert(host.status("A") == PluginStatus::Loaded);
    assert(host.status("B") == PluginStatus::Loaded);
    printf("PASS: topo_linear\n");
}

static void test_topo_diamond() {
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
    assert(lr.loaded_order.size() == 4);
    auto pos = [&](const char *id) {
        auto it = std::find(lr.loaded_order.begin(), lr.loaded_order.end(), id);
        assert(it != lr.loaded_order.end());
        return static_cast<int>(it - lr.loaded_order.begin());
    };
    assert(pos("D") < pos("B"));
    assert(pos("D") < pos("C"));
    assert(pos("B") < pos("A"));
    assert(pos("C") < pos("A"));
    printf("PASS: topo_diamond\n");
}

static void test_soft_dep_missing() {
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
    assert(a.load_count == 1);
    assert(host.status("A") == PluginStatus::Loaded);
    assert(host.fail_reason("A") == PluginFailReason::None);
    printf("PASS: soft_dep_missing\n");
}

static void test_soft_dep_present() {
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
    assert(lr.loaded_order.size() == 2);
    assert(lr.loaded_order[0] == "Z");
    assert(lr.loaded_order[1] == "A");
    printf("PASS: soft_dep_present\n");
}

static void test_hard_dep_missing() {
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
    assert(a.load_count == 0);
    assert(host.status("A") == PluginStatus::Failed);
    assert(host.fail_reason("A") == PluginFailReason::MissingHardDep);
    printf("PASS: hard_dep_missing\n");
}

static void test_conflict_both_enabled() {
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
    assert(a.load_count == 0 && b.load_count == 0);
    assert(host.status("A") == PluginStatus::Failed);
    assert(host.status("B") == PluginStatus::Failed);
    assert(host.fail_reason("A") == PluginFailReason::Conflict);
    assert(host.fail_reason("B") == PluginFailReason::Conflict);
    printf("PASS: conflict_both_enabled\n");
}

static void test_conflict_one_enabled() {
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
    assert(a.load_count == 1);
    assert(b.load_count == 0);
    assert(host.status("A") == PluginStatus::Loaded);
    assert(host.status("B") == PluginStatus::Disabled);
    printf("PASS: conflict_one_enabled\n");
}

static void test_cycle_three() {
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
    assert(a.load_count == 0 && b.load_count == 0 && c.load_count == 0);
    assert(host.status("A") == PluginStatus::Failed);
    assert(host.status("B") == PluginStatus::Failed);
    assert(host.status("C") == PluginStatus::Failed);
    assert(host.fail_reason("A") == PluginFailReason::Cycle);
    printf("PASS: cycle_three\n");
}

static void test_phase_barrier() {
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
    assert(early.loaded_order.size() == 1);
    assert(early.loaded_order[0] == "X");
    assert(y.load_count == 0);
    auto late = host.load_phase(PluginPhase::AfterModMain);
    assert(late.loaded_order.size() == 1);
    assert(late.loaded_order[0] == "Y");
    assert(y.load_count == 1);
    printf("PASS: phase_barrier\n");
}

static void test_phase_skip_disabled() {
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
    assert(a.load_count == 0);
    assert(host.status("A") == PluginStatus::Disabled);
    printf("PASS: phase_skip_disabled\n");
}

static void test_load_throw_fails_dependents() {
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
    assert(b.load_count == 1);
    assert(a.load_count == 0);
    assert(c.load_count == 0);
    assert(host.status("B") == PluginStatus::Loaded);
    assert(host.status("A") == PluginStatus::Failed);
    assert(host.fail_reason("A") == PluginFailReason::LoadThrew);
    assert(host.status("C") == PluginStatus::Failed);
    assert(host.fail_reason("C") == PluginFailReason::MissingHardDep);
    printf("PASS: load_throw_fails_dependents\n");
}

static void test_priority_tiebreak() {
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
    assert(lr.loaded_order.size() == 2);
    assert(lr.loaded_order[0] == "A");
    assert(lr.loaded_order[1] == "B");
    printf("PASS: priority_tiebreak\n");
}

static void test_profiler_before_hide() {
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
    assert(lr.loaded_order.size() == 2);
    assert(lr.loaded_order[0] == "debug.profiler");
    assert(lr.loaded_order[1] == "jit.runtime");
    printf("PASS: profiler_before_hide\n");
}

static void test_sticky_no_unload() {
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
    assert(!host.unload_plugin("A", ctx));
    assert(a.unload_count == 0);
    assert(host.status("A") == PluginStatus::Loaded);
    printf("PASS: sticky_no_unload\n");
}

static void test_reload_unload() {
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
    assert(host.unload_plugin("A", ctx));
    assert(a.unload_count == 1);
    printf("PASS: reload_unload\n");
}

static void test_network_rpc_option_matrix() {
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
        assert(lr.ok);
        assert(lr.loaded_order.size() == 1);
        assert(lr.loaded_order[0] == "network.rpc");
        assert(rpc.load_count == 1);
        assert(host.status("network.rpc") == PluginStatus::Loaded);
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
        assert(lr.ok);
        assert(lr.loaded_order.empty());
        assert(rpc.load_count == 0);
        assert(host.status("network.rpc") == PluginStatus::Disabled);
    }
    printf("PASS: network_rpc_option_matrix\n");
}

static void test_network_entity_hard_dep_on_rpc() {
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
        assert(host.status("network.rpc") == PluginStatus::Disabled);
        assert(host.status("network.entity") == PluginStatus::Failed);
        assert(host.fail_reason("network.entity") == PluginFailReason::MissingHardDep);
        assert(std::find(rr.failed.begin(), rr.failed.end(), "network.entity") != rr.failed.end());
        host.load_phase(PluginPhase::EarlyNative);
        host.load_phase(PluginPhase::AfterModMain);
        assert(rpc.load_count == 0);
        assert(entity.load_count == 0);
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
        assert(rr.failed.empty());
        assert(host.status("network.rpc") == PluginStatus::Registered);
        assert(host.status("network.entity") == PluginStatus::Registered);

        auto lr_early = host.load_phase(PluginPhase::EarlyNative);
        assert(lr_early.ok);
        assert(lr_early.loaded_order.size() == 1);
        assert(lr_early.loaded_order[0] == "network.rpc");
        assert(rpc.load_count == 1);

        auto lr_late = host.load_phase(PluginPhase::AfterModMain);
        assert(lr_late.ok);
        assert(entity.load_count == 1);
        assert(host.status("network.entity") == PluginStatus::Loaded);
        assert(host.status("network.rpc") == PluginStatus::Loaded);
        // entity after rpc within AfterModMain when both phases load
        auto pos_rpc = std::find(lr_late.loaded_order.begin(), lr_late.loaded_order.end(), "network.rpc");
        auto pos_ent = std::find(lr_late.loaded_order.begin(), lr_late.loaded_order.end(), "network.entity");
        assert(pos_ent != lr_late.loaded_order.end());
        if (pos_rpc != lr_late.loaded_order.end()) {
            assert(pos_rpc < pos_ent);
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
        assert(host.status("network.rpc") == PluginStatus::Registered);
        assert(host.status("network.entity") == PluginStatus::Disabled);
        host.load_phase(PluginPhase::EarlyNative);
        host.load_phase(PluginPhase::AfterModMain);
        assert(rpc.load_count >= 1);
        assert(entity.load_count == 0);
    }

    printf("PASS: network_entity_hard_dep_on_rpc\n");
}

int main() {
    test_empty_registry();
    test_topo_linear();
    test_topo_diamond();
    test_soft_dep_missing();
    test_soft_dep_present();
    test_hard_dep_missing();
    test_conflict_both_enabled();
    test_conflict_one_enabled();
    test_cycle_three();
    test_phase_barrier();
    test_phase_skip_disabled();
    test_load_throw_fails_dependents();
    test_priority_tiebreak();
    test_profiler_before_hide();
    test_sticky_no_unload();
    test_reload_unload();
    test_network_rpc_option_matrix();
    test_network_entity_hard_dep_on_rpc();
    printf("All host graph tests passed!\n");
    return 0;
}
