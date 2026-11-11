#include "config/CascadeEngine.hpp"
#include "config/IConfigSource.hpp"
#include "config/ResolvedConfig.hpp"
#include "config/ConfigSchema.hpp"
#include "plugins/plugin_core_vm/VmConfig.hpp"
#include "plugins/plugin_core_vm/GameLuaType.hpp"
#include <ostream>
#include <vector>
#include <doctest/doctest.h>

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

TEST_CASE("test_config_resolve/resolve_respects_source_order_and_whitelist") {
    ConfigSchemaRegistry reg;
    // SaveFile + ModinfoDefault only — EnvOrCmd blocked
    REQUIRE(reg.add(bool_key(
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

    REQUIRE_EQ(resolved.view.count("EnableNetSim"), 1);
    REQUIRE_EQ(resolved.view.at("EnableNetSim").b, true);
    REQUIRE_EQ(resolved.source_of.at("EnableNetSim"), ConfigSource::SaveFile);
}

TEST_CASE("test_config_resolve/resolve_empty_sources_yields_empty_view") {
    ConfigSchemaRegistry reg;
    REQUIRE(reg.add(bool_key("NetworkOpt", true, kConfigSourceAll)));
    CascadeContext ctx;
    std::vector<const IConfigSource *> sources;
    auto resolved = resolve(reg, ctx, sources);
    REQUIRE(resolved.view.empty());
    REQUIRE(resolved.source_of.empty());
}

TEST_CASE("test_config_resolve/resolve_env_lua_vm_type_aliases") {
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

    REQUIRE_EQ(resolved.view.count("LuaVmType"), 1);
    REQUIRE_EQ(resolved.view.at("LuaVmType").type, ConfigValueType::String);
    REQUIRE_EQ(resolved.view.at("LuaVmType").s, "lua51");
    REQUIRE_EQ(resolved.source_of.at("LuaVmType"), ConfigSource::EnvOrCmd);
    REQUIRE_EQ(resolved.view.count("EnabledGenGC"), 0);

    // Emulate EnvOrCmdSource::read for jit_gen → LuaVmType=jit + EnabledGenGC=true.
    ConfigView env_jit_gen;
    env_jit_gen["LuaVmType"] = ConfigValue::string("jit");
    env_jit_gen["EnabledGenGC"] = ConfigValue::boolean(true);
    FakeSource env_gen(ConfigSource::EnvOrCmd, env_jit_gen);
    const std::vector<const IConfigSource *> sources_gen = {&env_gen};
    auto resolved_gen = resolve(reg, ctx, sources_gen);

    REQUIRE_EQ(resolved_gen.view.at("LuaVmType").s, "jit");
    REQUIRE_EQ(resolved_gen.view.at("EnabledGenGC").type, ConfigValueType::Bool);
    REQUIRE_EQ(resolved_gen.view.at("EnabledGenGC").b, true);
    REQUIRE_EQ(resolved_gen.source_of.at("LuaVmType"), ConfigSource::EnvOrCmd);
    REQUIRE_EQ(resolved_gen.source_of.at("EnabledGenGC"), ConfigSource::EnvOrCmd);

    // _51 alias accepted by schema.allowed.
    ConfigView env_51;
    env_51["LuaVmType"] = ConfigValue::string("_51");
    FakeSource env_u51(ConfigSource::EnvOrCmd, env_51);
    const std::vector<const IConfigSource *> sources_51 = {&env_u51};
    auto resolved_51 = resolve(reg, ctx, sources_51);
    REQUIRE_EQ(resolved_51.view.at("LuaVmType").s, "_51");

    // Without VM schema, LuaVmType is unknown and ignored (soft optional).
    ConfigSchemaRegistry base_only;
    RegisterCoreOptionSchema(base_only);
    REQUIRE_EQ(base_only.find("LuaVmType"), nullptr);
    FakeSource env_no_schema(ConfigSource::EnvOrCmd, env_lua51);
    const std::vector<const IConfigSource *> sources_no = {&env_no_schema};
    auto resolved_no = resolve(base_only, ctx, sources_no);
    REQUIRE_EQ(resolved_no.view.count("LuaVmType"), 0);
}

TEST_CASE("test_config_resolve/identity_keys_luajit_only") {
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

    REQUIRE_EQ(resolved.view.at("modmain_path").s, "mods/workshop-123/modmain.lua");
    REQUIRE_EQ(resolved.view.at("modname").s, "workshop-123");
    REQUIRE_EQ(resolved.view.at("modid").s, "123");
    REQUIRE_EQ(resolved.source_of.at("modmain_path"), ConfigSource::LuajitConfig);
    REQUIRE_EQ(resolved.source_of.at("modname"), ConfigSource::LuajitConfig);
    REQUIRE_EQ(resolved.source_of.at("modid"), ConfigSource::LuajitConfig);

    // Accessors fall back to view
    REQUIRE_EQ(resolved.modmain_path(), "mods/workshop-123/modmain.lua");
    REQUIRE_EQ(resolved.modname(), "workshop-123");
    REQUIRE_EQ(resolved.modid(), "123");
}

TEST_CASE("test_config_resolve/enabled_gen_gc_excludes_luajit") {
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
        REQUIRE_EQ(resolved.view.at("EnabledGenGC").b, false);
        REQUIRE_EQ(resolved.source_of.at("EnabledGenGC"), ConfigSource::ModinfoDefault);
        REQUIRE_FALSE(ds::core_vm::enabled_gen_gc(resolved));
    }
    // SaveFile may set it.
    {
        const std::vector<const IConfigSource *> sources = {&def, &luajit, &save_src};
        auto resolved = resolve(reg, ctx, sources);
        REQUIRE_EQ(resolved.view.at("EnabledGenGC").b, true);
        REQUIRE_EQ(resolved.source_of.at("EnabledGenGC"), ConfigSource::SaveFile);
        REQUIRE(ds::core_vm::enabled_gen_gc(resolved));
    }
}

TEST_CASE("test_config_resolve/resolved_config_accessors") {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    RegisterCoreVmOptionSchema(reg);
    // Business keys owned by plugins in production; seed AngleBackend here for
    // accessor coverage (OB-S4 — no L0 RegisterBuiltinBusinessOptionSchema).
    {
        OptionSchemaEntry e;
        e.key = "AngleBackend";
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("auto");
        e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};
        e.allowed_sources =
            static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault) |
            static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
            static_cast<ConfigSourceMask>(ConfigSource::EnvOrCmd);
        REQUIRE(reg.add(std::move(e)));
    }

    ConfigView values;
    values["DisableJITWhenServer"] = ConfigValue::boolean(true);
    values["LuaVmType"] = ConfigValue::string("jit");
    values["EnabledGenGC"] = ConfigValue::boolean(true);
    values["AngleBackend"] = ConfigValue::string("vulkan");
    values["modname"] = ConfigValue::string("workshop-9");
    FakeSource env(ConfigSource::EnvOrCmd, values);
    FakeSource lj(ConfigSource::LuajitConfig, values);

    CascadeContext ctx;
    ctx.modname = "ctx-fallback";
    // VM options allow all sources; identity only Luajit.
    const std::vector<const IConfigSource *> sources = {&lj, &env};
    auto resolved = resolve(reg, ctx, sources);

    REQUIRE(ds::core_vm::disable_jit_when_server(resolved));
    REQUIRE(ds::core_vm::enabled_gen_gc(resolved));
    REQUIRE_EQ(ds::core_vm::lua_vm_type_string(resolved), "jit");
    REQUIRE_EQ(ds::core_vm::get_lua_vm_type(resolved), GameLuaType::jit_gen); // EnabledGenGC wins
    REQUIRE(resolved.string_opt("AngleBackend") == std::optional<std::string_view>{"vulkan"});
    REQUIRE_EQ(resolved.modname(), "workshop-9");
}

// write-back removed: no map_to_game_jit_mod_config / has_vm_options.


// Generic unknown-key behaviour: a key absent from the schema is dropped by
// apply_partial(). Production reaches this only for keys no plugin owns — the VM
// trio is seeded by BuildCascadeSchema(), business keys by plugin_core_vm's peers.
TEST_CASE("test_config_resolve/resolve_without_vm_schema_omits_vm_keys") {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);

    ConfigView defaults;
    defaults["AlwaysEnableMod"] = ConfigValue::boolean(false); // stale user configuration
    FakeSource modinfo(ConfigSource::ModinfoDefault, defaults);

    CascadeContext ctx;
    const std::vector<const IConfigSource *> sources = {&modinfo};
    auto resolved = resolve(reg, ctx, sources);

    REQUIRE_EQ(resolved.view.count("LuaVmType"), 0);
    REQUIRE_EQ(resolved.view.count("EnabledGenGC"), 0);
    REQUIRE_EQ(resolved.view.count("DisableJITWhenServer"), 0);
    REQUIRE_EQ(resolved.view.count("AlwaysEnableMod"), 0);
}

// Regression: the cascade schema must carry the VM trio without any plugin
// module_init. DynamicPluginLoader can skip plugin_core_vm (load_failed /
// abi_mismatch / missing_init / init_failed / duplicate_stem) while
// CoreVmBootstrap still maps the DLL by path and only runs
// ds_core_vm_run_signature_and_replace, so nothing registers the keys. Since
// apply_partial() drops unknown keys, a missing LuaVmType loses `lua_vm_type`,
// the modinfo default and modoverrides at once, resolves to
// GameLuaType::unknown and degrades to the game VM — one extra vanilla-Lua boot
// plus a restart request.
TEST_CASE("test_config_resolve/cascade_schema_carries_vm_keys") {
    ConfigSchemaRegistry reg = BuildCascadeSchema(); // same call the session makes
    REQUIRE_NE(reg.find("LuaVmType"), nullptr);
    REQUIRE_NE(reg.find("EnabledGenGC"), nullptr);
    REQUIRE_NE(reg.find("DisableJITWhenServer"), nullptr);
    const std::string seeded_default = reg.find("LuaVmType")->default_value.s;

    ConfigView defaults;
    defaults["LuaVmType"] = ConfigValue::string("game"); // modinfo default
    FakeSource modinfo(ConfigSource::ModinfoDefault, defaults);

    ConfigView env;
    env["LuaVmType"] = ConfigValue::string("jit"); // lua_vm_type=jit
    FakeSource env_src(ConfigSource::EnvOrCmd, env);

    CascadeContext ctx;
    const std::vector<const IConfigSource *> sources = {&modinfo, &env_src};
    auto resolved = resolve(reg, ctx, sources);
    REQUIRE_EQ(resolved.view.count("LuaVmType"), 1);
    REQUIRE_EQ(resolved.view.at("LuaVmType").s, "jit");
    REQUIRE_EQ(resolved.source_of.at("LuaVmType"), ConfigSource::EnvOrCmd);
    REQUIRE_EQ(ds::core_vm::get_lua_vm_type(resolved), GameLuaType::jit);

    // refresh_cascade_after_plugins() re-adds plugin_core_vm's entries: identical
    // copies are a no-op, a divergent one returns false (the refresh logs it and
    // the seeded entry stays authoritative).
    const auto size_before = reg.size();
    RegisterCoreVmOptionSchema(reg);
    REQUIRE_EQ(reg.size(), size_before);

    OptionSchemaEntry divergent;
    divergent.key = "LuaVmType";
    divergent.type = ConfigValueType::String;
    divergent.default_value = ConfigValue::string("game");
    divergent.allowed = {"jit", "game"};
    divergent.allowed_sources = kConfigSourceAll;
    REQUIRE_FALSE(reg.add(std::move(divergent)));
    REQUIRE(reg.find("LuaVmType")->default_value.s == seeded_default);
}

} // namespace
