#include "config/ConfigSchema.hpp"
#include "config/BaseOptionKeys.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"

#include <algorithm>
#include <ostream>
#include <string>
#include <utility>
#include "config/ConfigSource.hpp"
#include <doctest/doctest.h>


using namespace ds::plugin;
using ds::config::keys::kDisableJITWhenServer;
using ds::config::keys::kEnabledGenGC;
using ds::config::keys::kLuaVmType;
using ds::config::keys::kModid;
using ds::config::keys::kModmainPath;
using ds::config::keys::kModname;
using ds::config::keys::kSaveFile;

TEST_CASE("test_config_schema/add_bool_find") {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    REQUIRE(reg.add(std::move(e)));
    REQUIRE_EQ(reg.size(), 1);

    const auto *found = reg.find("EnableVBPool");
    REQUIRE_NE(found, nullptr);
    REQUIRE(found->key == "EnableVBPool");
    REQUIRE(found->type == ConfigValueType::Bool);
    REQUIRE(found->default_value.type == ConfigValueType::Bool);
    REQUIRE(found->default_value.b == false);
}

TEST_CASE("test_config_schema/add_same_key_same_default") {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "EnableVBPool";
    e1.type = ConfigValueType::Bool;
    e1.default_value = ConfigValue::boolean(false);
    REQUIRE(reg.add(std::move(e1)));

    OptionSchemaEntry e2;
    e2.key = "EnableVBPool";
    e2.type = ConfigValueType::Bool;
    e2.default_value = ConfigValue::boolean(false);
    REQUIRE(reg.add(std::move(e2)));
    REQUIRE_EQ(reg.size(), 1);
}

TEST_CASE("test_config_schema/add_same_key_different_default") {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "EnableVBPool";
    e1.type = ConfigValueType::Bool;
    e1.default_value = ConfigValue::boolean(false);
    REQUIRE(reg.add(std::move(e1)));

    OptionSchemaEntry e2;
    e2.key = "EnableVBPool";
    e2.type = ConfigValueType::Bool;
    e2.default_value = ConfigValue::boolean(true);
    REQUIRE_FALSE(reg.add(std::move(e2)));
    REQUIRE_EQ(reg.size(), 1);

    const auto *found = reg.find("EnableVBPool");
    REQUIRE_NE(found, nullptr);
    REQUIRE(found->default_value.b == false);
}

TEST_CASE("test_config_schema/find_missing") {
    ConfigSchemaRegistry reg;
    REQUIRE_EQ(reg.find("MissingKey"), nullptr);
}

TEST_CASE("test_config_schema/register_core_option_schema") {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    // L0 base seed: 4 identity keys only; retired options must not re-enter the cascade.
    // VM keys (LuaVmType, EnabledGenGC, DisableJITWhenServer) are owned by
    // plugin_core_vm via RegisterCoreVmOptionSchema.
    REQUIRE_EQ(reg.size(), 4);
    REQUIRE_EQ(reg.find("AlwaysEnableMod"), nullptr);
    REQUIRE_NE(reg.find(std::string{kModmainPath}), nullptr);
    REQUIRE_NE(reg.find(std::string{kModname}), nullptr);
    REQUIRE_NE(reg.find(std::string{kModid}), nullptr);
    REQUIRE_NE(reg.find(std::string{kSaveFile}), nullptr);

    // Step 1 acceptance: RegisterCore alone has no VM keys.
    REQUIRE_EQ(reg.find(std::string{kLuaVmType}), nullptr);
    REQUIRE_EQ(reg.find(std::string{kEnabledGenGC}), nullptr);
    REQUIRE_EQ(reg.find(std::string{kDisableJITWhenServer}), nullptr);

    constexpr auto kLuajitOnly =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::LuajitConfig);
    constexpr auto kSaveOnly =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile);

    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kModmainPath})->allowed_sources), kLuajitOnly);
    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kModname})->allowed_sources), kLuajitOnly);
    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kModid})->allowed_sources), kLuajitOnly);
    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kSaveFile})->allowed_sources), kSaveOnly);

    // Identity key types
    REQUIRE(reg.find(std::string{kModmainPath})->type == ConfigValueType::String);
    REQUIRE(reg.find(std::string{kModname})->type == ConfigValueType::String);
    REQUIRE(reg.find(std::string{kModid})->type == ConfigValueType::String);
    REQUIRE(reg.find(std::string{kSaveFile})->type == ConfigValueType::String);

    // Constants match wire names (OptionKeys SSOT).
    REQUIRE_EQ(kDisableJITWhenServer, "DisableJITWhenServer");
    REQUIRE_EQ(kLuaVmType, "LuaVmType");
    REQUIRE_EQ(kEnabledGenGC, "EnabledGenGC");
    REQUIRE_EQ(kModmainPath, "modmain_path");
    REQUIRE_EQ(kModname, "modname");
    REQUIRE_EQ(kModid, "modid");
    REQUIRE_EQ(kSaveFile, "save_file");

    // Idempotent re-register.
    RegisterCoreOptionSchema(reg);
    REQUIRE_EQ(reg.size(), 4);
}

TEST_CASE("test_config_schema/register_core_vm_option_schema") {
    ConfigSchemaRegistry reg;
    RegisterCoreVmOptionSchema(reg);
    REQUIRE_EQ(reg.size(), 3);
    REQUIRE_NE(reg.find(std::string{kLuaVmType}), nullptr);
    REQUIRE_NE(reg.find(std::string{kEnabledGenGC}), nullptr);
    REQUIRE_NE(reg.find(std::string{kDisableJITWhenServer}), nullptr);

    const auto *lua_vm = reg.find(std::string{kLuaVmType});
    REQUIRE(lua_vm->type == ConfigValueType::String);
    REQUIRE(lua_vm->default_value.s == "jit");
    REQUIRE_FALSE(lua_vm->allowed.empty());
    auto has_allowed = [&](const char *v) {
        return std::find(lua_vm->allowed.begin(), lua_vm->allowed.end(), v) !=
               lua_vm->allowed.end();
    };
    REQUIRE(has_allowed("jit"));
    REQUIRE(has_allowed("game"));
    REQUIRE(has_allowed("lua51"));
    REQUIRE(has_allowed("51"));
    REQUIRE(has_allowed("5.1"));
    REQUIRE(has_allowed("_51"));
    REQUIRE(has_allowed("jit_gen"));

    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);

    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kDisableJITWhenServer})->allowed_sources), ds::config::kConfigSourceAll);
    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kLuaVmType})->allowed_sources), ds::config::kConfigSourceAll);
    REQUIRE_EQ(ds::config::effective_sources(reg.find(std::string{kEnabledGenGC})->allowed_sources), kDefaultSaveEnv);

    // Combined L0 + VM excludes the retired AlwaysEnableMod key.
    RegisterCoreOptionSchema(reg);
    REQUIRE_EQ(reg.size(), 7);
    REQUIRE_EQ(reg.find("AlwaysEnableMod"), nullptr);

    // Idempotent re-register of VM keys.
    RegisterCoreVmOptionSchema(reg);
    REQUIRE_EQ(reg.size(), 7);
}


// Local stand-in for former L0 RegisterBuiltinBusinessOptionSchema — production
// ownership is plugin module_init (OB-S4). Keeps coerce/mask coverage green.
static void register_business_schema_for_tests(ConfigSchemaRegistry &r) {
    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    {
        OptionSchemaEntry e;
        e.key = "AngleBackend";
        e.type = ConfigValueType::String;
        e.default_value = ConfigValue::string("auto");
        e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
    for (const auto &[key, def] :
         std::initializer_list<std::pair<const char *, bool>>{
             {"EnableVBPool", false},
             {"NetworkOpt", true},
             {"EnableNetSim", false},
             {"EnableForkSave", true},
             {"EnableLagCompensation", false},
         }) {
        OptionSchemaEntry e;
        e.key = key;
        e.type = ConfigValueType::Bool;
        e.default_value = ConfigValue::boolean(def);
        e.allowed_sources = kDefaultSaveEnv;
        (void) r.add(std::move(e));
    }
}

TEST_CASE("test_config_schema/l0_core_has_no_business_keys") {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    REQUIRE_EQ(reg.find("AngleBackend"), nullptr);
    REQUIRE_EQ(reg.find("EnableVBPool"), nullptr);
    REQUIRE_EQ(reg.find("NetworkOpt"), nullptr);
    REQUIRE_EQ(reg.find("EnableNetSim"), nullptr);
    REQUIRE_EQ(reg.find("EnableForkSave"), nullptr);
    REQUIRE_EQ(reg.find("EnableLagCompensation"), nullptr);
}

TEST_CASE("test_config_schema/business_schema_masks_match_plugins") {
    ConfigSchemaRegistry reg;
    register_business_schema_for_tests(reg);
    REQUIRE_NE(reg.find("AngleBackend"), nullptr);
    REQUIRE_NE(reg.find("EnableVBPool"), nullptr);
    REQUIRE_NE(reg.find("NetworkOpt"), nullptr);
    REQUIRE_NE(reg.find("EnableNetSim"), nullptr);
    REQUIRE_NE(reg.find("EnableForkSave"), nullptr);
    REQUIRE_NE(reg.find("EnableLagCompensation"), nullptr);

    const auto *angle = reg.find("AngleBackend");
    REQUIRE(angle->type == ConfigValueType::String);
    REQUIRE(angle->default_value.s == "auto");
    REQUIRE(angle->allowed.size() == 4);

    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    REQUIRE_EQ(ds::config::effective_sources(angle->allowed_sources), kDefaultSaveEnv);
    REQUIRE_EQ(ds::config::effective_sources(reg.find("EnableVBPool")->allowed_sources), kDefaultSaveEnv);
    REQUIRE_EQ(ds::config::effective_sources(reg.find("NetworkOpt")->allowed_sources), kDefaultSaveEnv);
    REQUIRE_EQ(ds::config::effective_sources(reg.find("EnableNetSim")->allowed_sources), kDefaultSaveEnv);
    REQUIRE_EQ(ds::config::effective_sources(reg.find("EnableForkSave")->allowed_sources), kDefaultSaveEnv);
    REQUIRE_EQ(ds::config::effective_sources(reg.find("EnableLagCompensation")->allowed_sources), kDefaultSaveEnv);

    REQUIRE_EQ(reg.find("TotallyUnknownOption"), nullptr);
}


TEST_CASE("test_config_schema/try_coerce_bool") {
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);

    ConfigValue out;
    REQUIRE(TryCoerceSavedBool(true, e, out));
    REQUIRE_EQ(out.type, ConfigValueType::Bool);
    REQUIRE_EQ(out.b, true);

    REQUIRE(TryCoerceSavedNumber(1.0, e, out));
    REQUIRE_EQ(out.type, ConfigValueType::Bool);
    REQUIRE_EQ(out.b, true);
    REQUIRE(TryCoerceSavedNumber(0.0, e, out));
    REQUIRE_EQ(out.type, ConfigValueType::Bool);
    REQUIRE_EQ(out.b, false);

    REQUIRE(TryCoerceSavedString("true", e, out));
    REQUIRE_EQ(out.b, true);
    REQUIRE(TryCoerceSavedString("0", e, out));
    REQUIRE_EQ(out.b, false);
    REQUIRE_FALSE(TryCoerceSavedString("maybe", e, out));
}

TEST_CASE("test_config_schema/try_coerce_string_allowed") {
    OptionSchemaEntry e;
    e.key = "AngleBackend";
    e.type = ConfigValueType::String;
    e.default_value = ConfigValue::string("auto");
    e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};

    ConfigValue out;
    REQUIRE(TryCoerceSavedString("vulkan", e, out));
    REQUIRE_EQ(out.type, ConfigValueType::String);
    REQUIRE_EQ(out.s, "vulkan");

    // Invalid membership → fail (caller keeps default).
    REQUIRE_FALSE(TryCoerceSavedString("metal", e, out));

    // Wrong type helpers fail.
    REQUIRE_FALSE(TryCoerceSavedBool(true, e, out));
}

TEST_CASE("test_config_schema/try_coerce_number") {
    OptionSchemaEntry e;
    e.key = "TargetRenderFPS";
    e.type = ConfigValueType::Number;
    e.default_value = ConfigValue::number(60);

    ConfigValue out;
    REQUIRE(TryCoerceSavedNumber(144.0, e, out));
    REQUIRE_EQ(out.type, ConfigValueType::Number);
    REQUIRE_EQ(out.n, 144.0);
    REQUIRE_FALSE(TryCoerceSavedString("144", e, out));
}

TEST_CASE("test_config_schema/unknown_key_ignored_pattern") {
    // Mirrors save-loop: find returns nullptr → skip without error.
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    register_business_schema_for_tests(reg);

    REQUIRE_NE(reg.find("NetworkOpt"), nullptr);
    REQUIRE_EQ(reg.find("NotARealOption"), nullptr);

    // Coerce only runs when schema is found.
    const auto *sch = reg.find("NetworkOpt");
    ConfigValue out;
    REQUIRE(TryCoerceSavedBool(false, *sch, out));
    REQUIRE_EQ(out.b, false);
}

TEST_CASE("test_config_schema/effective_sources_zero_means_all") {
    using namespace ds::config;
    REQUIRE_EQ(effective_sources(0), kConfigSourceAll);
    REQUIRE(source_allowed(0, ConfigSource::EnvOrCmd));
    REQUIRE(source_allowed(kConfigSourceAll, ConfigSource::SaveFile));
    ConfigSourceMask save_only = static_cast<ConfigSourceMask>(ConfigSource::SaveFile);
    REQUIRE(source_allowed(save_only, ConfigSource::SaveFile));
    REQUIRE_FALSE(source_allowed(save_only, ConfigSource::EnvOrCmd));
}

TEST_CASE("test_config_schema/add_same_key_different_allowed_sources_conflicts") {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "AngleBackend";
    e1.type = ConfigValueType::String;
    e1.default_value = ConfigValue::string("auto");
    e1.allowed_sources = ds::config::kConfigSourceAll;
    REQUIRE(reg.add(e1));

    OptionSchemaEntry e2 = e1;
    e2.allowed_sources = static_cast<ds::config::ConfigSourceMask>(
        ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault);
    // excludes LuajitConfig
    REQUIRE_FALSE(reg.add(std::move(e2)));
}
