#include "config/CascadeEngine.hpp"
#include "config/IConfigSource.hpp"
#include "config/ResolvedConfig.hpp"
#include "config/ConfigSchema.hpp"
#include "config/Compat.hpp"
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
    RegisterCoreVmOptionSchema(reg);

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

    // Without VM schema, LuaVmType is unknown and ignored (soft optional).
    ConfigSchemaRegistry base_only;
    RegisterCoreOptionSchema(base_only);
    assert(base_only.find("LuaVmType") == nullptr);
    FakeSource env_no_schema(ConfigSource::EnvOrCmd, env_lua51);
    const std::vector<const IConfigSource *> sources_no = {&env_no_schema};
    auto resolved_no = resolve(base_only, ctx, sources_no);
    assert(resolved_no.view.count("LuaVmType") == 0);

    printf("PASS: resolve_env_lua_vm_type_aliases\n");
}

void test_identity_keys_luajit_only() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);

    ConfigView luajit;
    luajit["modmain_path"] = ConfigValue::string("mods/workshop-123/modmain.lua");
    luajit["modname"] = ConfigValue::string("workshop-123");
    luajit["modid"] = ConfigValue::string("123");
    FakeSource lj(ConfigSource::LuajitConfig, luajit);

    ConfigView save_try;
    save_try["modmain_path"] = ConfigValue::string("should_not_apply");
    save_try["modname"] = ConfigValue::string("evil");
    FakeSource save(ConfigSource::SaveFile, save_try);

    ConfigView env_try;
    env_try["modid"] = ConfigValue::string("env-id");
    FakeSource env(ConfigSource::EnvOrCmd, env_try);

    CascadeContext ctx;
    const std::vector<const IConfigSource *> sources = {&lj, &save, &env};
    auto resolved = resolve(reg, ctx, sources);

    assert(resolved.view.at("modmain_path").s == "mods/workshop-123/modmain.lua");
    assert(resolved.view.at("modname").s == "workshop-123");
    assert(resolved.view.at("modid").s == "123");
    assert(resolved.source_of.at("modmain_path") == ConfigSource::LuajitConfig);
    assert(resolved.source_of.at("modname") == ConfigSource::LuajitConfig);
    assert(resolved.source_of.at("modid") == ConfigSource::LuajitConfig);

    // Accessors fall back to view
    assert(resolved.modmain_path() == "mods/workshop-123/modmain.lua");
    assert(resolved.modname() == "workshop-123");
    assert(resolved.modid() == "123");

    printf("PASS: identity_keys_luajit_only\n");
}

void test_enabled_gen_gc_excludes_luajit() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    RegisterCoreVmOptionSchema(reg);

    ConfigView defaults;
    defaults["EnabledGenGC"] = ConfigValue::boolean(false);
    FakeSource def(ConfigSource::ModinfoDefault, defaults);

    ConfigView lj;
    lj["EnabledGenGC"] = ConfigValue::boolean(true);
    FakeSource luajit(ConfigSource::LuajitConfig, lj);

    ConfigView save;
    save["EnabledGenGC"] = ConfigValue::boolean(true);
    FakeSource save_src(ConfigSource::SaveFile, save);

    CascadeContext ctx;
    // Luajit alone must not set EnabledGenGC (mask excludes it).
    {
        const std::vector<const IConfigSource *> sources = {&def, &luajit};
        auto resolved = resolve(reg, ctx, sources);
        assert(resolved.view.at("EnabledGenGC").b == false);
        assert(resolved.source_of.at("EnabledGenGC") == ConfigSource::ModinfoDefault);
        assert(!resolved.enabled_gen_gc());
    }
    // SaveFile may set it.
    {
        const std::vector<const IConfigSource *> sources = {&def, &luajit, &save_src};
        auto resolved = resolve(reg, ctx, sources);
        assert(resolved.view.at("EnabledGenGC").b == true);
        assert(resolved.source_of.at("EnabledGenGC") == ConfigSource::SaveFile);
        assert(resolved.enabled_gen_gc());
    }
    printf("PASS: enabled_gen_gc_excludes_luajit\n");
}

void test_resolved_config_accessors() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    RegisterCoreVmOptionSchema(reg);
    RegisterBuiltinBusinessOptionSchema(reg);

    ConfigView values;
    values["AlwaysEnableMod"] = ConfigValue::boolean(true);
    values["DisableJITWhenServer"] = ConfigValue::boolean(true);
    values["LuaVmType"] = ConfigValue::string("jit");
    values["EnabledGenGC"] = ConfigValue::boolean(true);
    values["AngleBackend"] = ConfigValue::string("vulkan");
    values["modname"] = ConfigValue::string("workshop-9");
    FakeSource env(ConfigSource::EnvOrCmd, values);
    FakeSource lj(ConfigSource::LuajitConfig, values);

    CascadeContext ctx;
    ctx.modname = "ctx-fallback";
    // AlwaysEnableMod etc. All sources; identity only Luajit.
    const std::vector<const IConfigSource *> sources = {&lj, &env};
    auto resolved = resolve(reg, ctx, sources);

    assert(resolved.always_enable_mod());
    assert(resolved.disable_jit_when_server());
    assert(resolved.enabled_gen_gc());
    assert(resolved.lua_vm_type() == "jit");
    assert(resolved.get_lua_vm_type() == GameLuaType::jit_gen); // EnabledGenGC wins
    assert(resolved.angle_backend() == "vulkan");
    assert(resolved.modname() == "workshop-9");

    printf("PASS: resolved_config_accessors\n");
}

// OB-S2: resolve without VM schema must not project bag VM fields as "present"
// for client save write-back (empty/false defaults would wipe user save).
void test_map_without_vm_schema_skips_vm_write_back_flag() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    // No RegisterCoreVmOptionSchema — plugin_core_vm absent.

    ConfigView defaults;
    defaults["AlwaysEnableMod"] = ConfigValue::boolean(true);
    FakeSource modinfo(ConfigSource::ModinfoDefault, defaults);

    CascadeContext ctx;
    const std::vector<const IConfigSource *> sources = {&modinfo};
    auto resolved = resolve(reg, ctx, sources);

    assert(resolved.view.count("LuaVmType") == 0);
    assert(resolved.view.count("EnabledGenGC") == 0);
    assert(resolved.view.count("DisableJITWhenServer") == 0);
    assert(resolved.view.count("AlwaysEnableMod") == 1);

    auto bag = map_to_game_jit_mod_config(resolved);
    assert(!bag.has_vm_options);
    assert(bag.LuaVmType.empty());
    assert(!bag.EnabledGenGC);
    assert(!bag.DisableJITWhenServer);
    assert(bag.AlwaysEnableMod);

    // With VM schema + defaults, flag is set and values project.
    RegisterCoreVmOptionSchema(reg);
    ConfigView vm_defaults;
    vm_defaults["AlwaysEnableMod"] = ConfigValue::boolean(false);
    vm_defaults["LuaVmType"] = ConfigValue::string("jit");
    vm_defaults["EnabledGenGC"] = ConfigValue::boolean(false);
    vm_defaults["DisableJITWhenServer"] = ConfigValue::boolean(true);
    FakeSource modinfo_vm(ConfigSource::ModinfoDefault, vm_defaults);
    const std::vector<const IConfigSource *> sources_vm = {&modinfo_vm};
    auto resolved_vm = resolve(reg, ctx, sources_vm);
    assert(resolved_vm.view.count("LuaVmType") == 1);

    auto bag_vm = map_to_game_jit_mod_config(resolved_vm);
    assert(bag_vm.has_vm_options);
    assert(bag_vm.LuaVmType == "jit");
    assert(bag_vm.DisableJITWhenServer);

    printf("PASS: map_without_vm_schema_skips_vm_write_back_flag\n");
}

} // namespace

int main() {
    test_resolve_respects_source_order_and_whitelist();
    test_resolve_empty_sources_yields_empty_view();
    test_resolve_env_lua_vm_type_aliases();
    test_identity_keys_luajit_only();
    test_enabled_gen_gc_excludes_luajit();
    test_resolved_config_accessors();
    test_map_without_vm_schema_skips_vm_write_back_flag();
    printf("ALL PASS: config_resolve\n");
    return 0;
}

