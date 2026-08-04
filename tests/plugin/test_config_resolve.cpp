#include "config/CascadeEngine.hpp"
#include "config/IConfigSource.hpp"
#include "config/ResolvedConfig.hpp"
#include "core/ConfigSchema.hpp"
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ds::plugin;
using namespace ds::config;

namespace {

OptionSchemaEntry bool_key(const char *k, bool def, ConfigSourceMask src) {
    OptionSchemaEntry e;
    e.key = k;
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(def);
    e.allowed_sources = src;
    return e;
}

class FakeSource final : public IConfigSource {
public:
    FakeSource(ConfigSource id, ConfigView values)
        : id_(id), values_(std::move(values)) {}

    ConfigSource id() const override { return id_; }
    ConfigPartial read(CascadeContext &) const override {
        ConfigPartial p;
        p.values = values_;
        return p;
    }

private:
    ConfigSource id_;
    ConfigView values_;
};

void test_resolve_respects_source_order_and_whitelist() {
    ConfigSchemaRegistry reg;
    // SaveFile + ModinfoDefault only — EnvOrCmd blocked
    assert(reg.add(bool_key(
        "EnableNetSim", false,
        static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
            static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault))));

    ConfigView defaults;
    defaults["EnableNetSim"] = ConfigValue::boolean(false);
    FakeSource modinfo(ConfigSource::ModinfoDefault, defaults);

    ConfigView save;
    save["EnableNetSim"] = ConfigValue::boolean(true);
    FakeSource save_src(ConfigSource::SaveFile, save);

    ConfigView env;
    env["EnableNetSim"] = ConfigValue::boolean(false);
    FakeSource env_src(ConfigSource::EnvOrCmd, env);

    CascadeContext ctx;
    const std::vector<const IConfigSource *> sources = {&modinfo, &save_src, &env_src};
    auto resolved = resolve(reg, ctx, sources);

    assert(resolved.view.count("EnableNetSim") == 1);
    assert(resolved.view.at("EnableNetSim").b == true);
    assert(resolved.source_of.at("EnableNetSim") == ConfigSource::SaveFile);
    printf("PASS: resolve_respects_source_order_and_whitelist\n");
}

void test_resolve_empty_sources_yields_empty_view() {
    ConfigSchemaRegistry reg;
    assert(reg.add(bool_key("NetworkOpt", true, kConfigSourceAll)));
    CascadeContext ctx;
    std::vector<const IConfigSource *> sources;
    auto resolved = resolve(reg, ctx, sources);
    assert(resolved.view.empty());
    assert(resolved.source_of.empty());
    printf("PASS: resolve_empty_sources_yields_empty_view\n");
}

void test_resolve_env_lua_vm_type_aliases() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);

    // Emulate EnvOrCmdSource::read output for lua51 aliases — raw string preserved.
    ConfigView env_lua51;
    env_lua51["LuaVmType"] = ConfigValue::string("lua51");
    FakeSource env_src(ConfigSource::EnvOrCmd, env_lua51);

    CascadeContext ctx;
    const std::vector<const IConfigSource *> sources = {&env_src};
    auto resolved = resolve(reg, ctx, sources);

    assert(resolved.view.count("LuaVmType") == 1);
    assert(resolved.view.at("LuaVmType").type == ConfigValueType::String);
    assert(resolved.view.at("LuaVmType").s == "lua51");
    assert(resolved.source_of.at("LuaVmType") == ConfigSource::EnvOrCmd);
    assert(resolved.view.count("EnabledGenGC") == 0);

    // Emulate EnvOrCmdSource::read for jit_gen → LuaVmType=jit + EnabledGenGC=true.
    ConfigView env_jit_gen;
    env_jit_gen["LuaVmType"] = ConfigValue::string("jit");
    env_jit_gen["EnabledGenGC"] = ConfigValue::boolean(true);
    FakeSource env_gen(ConfigSource::EnvOrCmd, env_jit_gen);
    const std::vector<const IConfigSource *> sources_gen = {&env_gen};
    auto resolved_gen = resolve(reg, ctx, sources_gen);

    assert(resolved_gen.view.at("LuaVmType").s == "jit");
    assert(resolved_gen.view.at("EnabledGenGC").type == ConfigValueType::Bool);
    assert(resolved_gen.view.at("EnabledGenGC").b == true);
    assert(resolved_gen.source_of.at("LuaVmType") == ConfigSource::EnvOrCmd);
    assert(resolved_gen.source_of.at("EnabledGenGC") == ConfigSource::EnvOrCmd);

    // _51 alias accepted by schema.allowed.
    ConfigView env_51;
    env_51["LuaVmType"] = ConfigValue::string("_51");
    FakeSource env_u51(ConfigSource::EnvOrCmd, env_51);
    const std::vector<const IConfigSource *> sources_51 = {&env_u51};
    auto resolved_51 = resolve(reg, ctx, sources_51);
    assert(resolved_51.view.at("LuaVmType").s == "_51");

    printf("PASS: resolve_env_lua_vm_type_aliases\n");
}


} // namespace

int main() {
    test_resolve_respects_source_order_and_whitelist();
    test_resolve_empty_sources_yields_empty_view();
    test_resolve_env_lua_vm_type_aliases();
    printf("ALL PASS: config_resolve\n");
    return 0;
}
