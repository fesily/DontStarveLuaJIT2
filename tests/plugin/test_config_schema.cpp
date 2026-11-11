#include "config/ConfigSchema.hpp"
#include "config/BaseOptionKeys.hpp"
#include "plugins/plugin_core_vm/VmOptionKeys.hpp"

#include <algorithm>
#include <cstdio>
#include <string>
#include <utility>
#include "config/ConfigSource.hpp"
#include "support/test_assert.hpp"


using namespace ds::plugin;
using ds::config::keys::kDisableJITWhenServer;
using ds::config::keys::kEnabledGenGC;
using ds::config::keys::kLuaVmType;
using ds::config::keys::kModid;
using ds::config::keys::kModmainPath;
using ds::config::keys::kModname;
using ds::config::keys::kSaveFile;

static void test_add_bool_find() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    DS_REQUIRE(reg.add(std::move(e)));
    DS_REQUIRE(reg.size() == 1);

    const auto *found = reg.find("EnableVBPool");
    DS_REQUIRE(found != nullptr);
    DS_REQUIRE(found->key == "EnableVBPool");
    DS_REQUIRE(found->type == ConfigValueType::Bool);
    DS_REQUIRE(found->default_value.type == ConfigValueType::Bool);
    DS_REQUIRE(found->default_value.b == false);
    printf("PASS: add_bool_find\n");
}

static void test_add_same_key_same_default() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "EnableVBPool";
    e1.type = ConfigValueType::Bool;
    e1.default_value = ConfigValue::boolean(false);
    DS_REQUIRE(reg.add(std::move(e1)));

    OptionSchemaEntry e2;
    e2.key = "EnableVBPool";
    e2.type = ConfigValueType::Bool;
    e2.default_value = ConfigValue::boolean(false);
    DS_REQUIRE(reg.add(std::move(e2)));
    DS_REQUIRE(reg.size() == 1);
    printf("PASS: add_same_key_same_default\n");
}

static void test_add_same_key_different_default() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "EnableVBPool";
    e1.type = ConfigValueType::Bool;
    e1.default_value = ConfigValue::boolean(false);
    DS_REQUIRE(reg.add(std::move(e1)));

    OptionSchemaEntry e2;
    e2.key = "EnableVBPool";
    e2.type = ConfigValueType::Bool;
    e2.default_value = ConfigValue::boolean(true);
    DS_REQUIRE(!reg.add(std::move(e2)));
    DS_REQUIRE(reg.size() == 1);

    const auto *found = reg.find("EnableVBPool");
    DS_REQUIRE(found != nullptr);
    DS_REQUIRE(found->default_value.b == false);
    printf("PASS: add_same_key_different_default\n");
}

static void test_find_missing() {
    ConfigSchemaRegistry reg;
    DS_REQUIRE(reg.find("MissingKey") == nullptr);
    printf("PASS: find_missing\n");
}

static void test_register_core_option_schema() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    // L0 base seed: 4 identity keys only; retired options must not re-enter the cascade.
    // VM keys (LuaVmType, EnabledGenGC, DisableJITWhenServer) are owned by
    // plugin_core_vm via RegisterCoreVmOptionSchema.
    DS_REQUIRE(reg.size() == 4);
    DS_REQUIRE(reg.find("AlwaysEnableMod") == nullptr);
    DS_REQUIRE(reg.find(std::string{kModmainPath}) != nullptr);
    DS_REQUIRE(reg.find(std::string{kModname}) != nullptr);
    DS_REQUIRE(reg.find(std::string{kModid}) != nullptr);
    DS_REQUIRE(reg.find(std::string{kSaveFile}) != nullptr);

    // Step 1 acceptance: RegisterCore alone has no VM keys.
    DS_REQUIRE(reg.find(std::string{kLuaVmType}) == nullptr);
    DS_REQUIRE(reg.find(std::string{kEnabledGenGC}) == nullptr);
    DS_REQUIRE(reg.find(std::string{kDisableJITWhenServer}) == nullptr);

    constexpr auto kLuajitOnly =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::LuajitConfig);
    constexpr auto kSaveOnly =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile);

    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kModmainPath})->allowed_sources) ==
           kLuajitOnly);
    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kModname})->allowed_sources) ==
           kLuajitOnly);
    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kModid})->allowed_sources) ==
           kLuajitOnly);
    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kSaveFile})->allowed_sources) ==
           kSaveOnly);

    // Identity key types
    DS_REQUIRE(reg.find(std::string{kModmainPath})->type == ConfigValueType::String);
    DS_REQUIRE(reg.find(std::string{kModname})->type == ConfigValueType::String);
    DS_REQUIRE(reg.find(std::string{kModid})->type == ConfigValueType::String);
    DS_REQUIRE(reg.find(std::string{kSaveFile})->type == ConfigValueType::String);

    // Constants match wire names (OptionKeys SSOT).
    DS_REQUIRE(kDisableJITWhenServer == "DisableJITWhenServer");
    DS_REQUIRE(kLuaVmType == "LuaVmType");
    DS_REQUIRE(kEnabledGenGC == "EnabledGenGC");
    DS_REQUIRE(kModmainPath == "modmain_path");
    DS_REQUIRE(kModname == "modname");
    DS_REQUIRE(kModid == "modid");
    DS_REQUIRE(kSaveFile == "save_file");

    // Idempotent re-register.
    RegisterCoreOptionSchema(reg);
    DS_REQUIRE(reg.size() == 4);
    printf("PASS: register_core_option_schema\n");
}

static void test_register_core_vm_option_schema() {
    ConfigSchemaRegistry reg;
    RegisterCoreVmOptionSchema(reg);
    DS_REQUIRE(reg.size() == 3);
    DS_REQUIRE(reg.find(std::string{kLuaVmType}) != nullptr);
    DS_REQUIRE(reg.find(std::string{kEnabledGenGC}) != nullptr);
    DS_REQUIRE(reg.find(std::string{kDisableJITWhenServer}) != nullptr);

    const auto *lua_vm = reg.find(std::string{kLuaVmType});
    DS_REQUIRE(lua_vm->type == ConfigValueType::String);
    DS_REQUIRE(lua_vm->default_value.s == "jit");
    DS_REQUIRE(!lua_vm->allowed.empty());
    auto has_allowed = [&](const char *v) {
        return std::find(lua_vm->allowed.begin(), lua_vm->allowed.end(), v) !=
               lua_vm->allowed.end();
    };
    DS_REQUIRE(has_allowed("jit"));
    DS_REQUIRE(has_allowed("game"));
    DS_REQUIRE(has_allowed("lua51"));
    DS_REQUIRE(has_allowed("51"));
    DS_REQUIRE(has_allowed("5.1"));
    DS_REQUIRE(has_allowed("_51"));
    DS_REQUIRE(has_allowed("jit_gen"));

    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);

    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kDisableJITWhenServer})->allowed_sources) ==
           ds::config::kConfigSourceAll);
    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kLuaVmType})->allowed_sources) ==
           ds::config::kConfigSourceAll);
    DS_REQUIRE(ds::config::effective_sources(reg.find(std::string{kEnabledGenGC})->allowed_sources) ==
           kDefaultSaveEnv);

    // Combined L0 + VM excludes the retired AlwaysEnableMod key.
    RegisterCoreOptionSchema(reg);
    DS_REQUIRE(reg.size() == 7);
    DS_REQUIRE(reg.find("AlwaysEnableMod") == nullptr);

    // Idempotent re-register of VM keys.
    RegisterCoreVmOptionSchema(reg);
    DS_REQUIRE(reg.size() == 7);
    printf("PASS: register_core_vm_option_schema\n");
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

static void test_l0_core_has_no_business_keys() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    DS_REQUIRE(reg.find("AngleBackend") == nullptr);
    DS_REQUIRE(reg.find("EnableVBPool") == nullptr);
    DS_REQUIRE(reg.find("NetworkOpt") == nullptr);
    DS_REQUIRE(reg.find("EnableNetSim") == nullptr);
    DS_REQUIRE(reg.find("EnableForkSave") == nullptr);
    DS_REQUIRE(reg.find("EnableLagCompensation") == nullptr);
    printf("PASS: l0_core_has_no_business_keys\n");
}

static void test_business_schema_masks_match_plugins() {
    ConfigSchemaRegistry reg;
    register_business_schema_for_tests(reg);
    DS_REQUIRE(reg.find("AngleBackend") != nullptr);
    DS_REQUIRE(reg.find("EnableVBPool") != nullptr);
    DS_REQUIRE(reg.find("NetworkOpt") != nullptr);
    DS_REQUIRE(reg.find("EnableNetSim") != nullptr);
    DS_REQUIRE(reg.find("EnableForkSave") != nullptr);
    DS_REQUIRE(reg.find("EnableLagCompensation") != nullptr);

    const auto *angle = reg.find("AngleBackend");
    DS_REQUIRE(angle->type == ConfigValueType::String);
    DS_REQUIRE(angle->default_value.s == "auto");
    DS_REQUIRE(angle->allowed.size() == 4);

    constexpr auto kDefaultSaveEnv =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    DS_REQUIRE(ds::config::effective_sources(angle->allowed_sources) == kDefaultSaveEnv);
    DS_REQUIRE(ds::config::effective_sources(reg.find("EnableVBPool")->allowed_sources) ==
           kDefaultSaveEnv);
    DS_REQUIRE(ds::config::effective_sources(reg.find("NetworkOpt")->allowed_sources) ==
           kDefaultSaveEnv);
    DS_REQUIRE(ds::config::effective_sources(reg.find("EnableNetSim")->allowed_sources) ==
           kDefaultSaveEnv);
    DS_REQUIRE(ds::config::effective_sources(reg.find("EnableForkSave")->allowed_sources) ==
           kDefaultSaveEnv);
    DS_REQUIRE(ds::config::effective_sources(reg.find("EnableLagCompensation")->allowed_sources) ==
           kDefaultSaveEnv);

    DS_REQUIRE(reg.find("TotallyUnknownOption") == nullptr);
    printf("PASS: business_schema_masks_match_plugins\n");
}


static void test_try_coerce_bool() {
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);

    ConfigValue out;
    DS_REQUIRE(TryCoerceSavedBool(true, e, out));
    DS_REQUIRE(out.type == ConfigValueType::Bool && out.b == true);

    DS_REQUIRE(TryCoerceSavedNumber(1.0, e, out));
    DS_REQUIRE(out.type == ConfigValueType::Bool && out.b == true);
    DS_REQUIRE(TryCoerceSavedNumber(0.0, e, out));
    DS_REQUIRE(out.type == ConfigValueType::Bool && out.b == false);

    DS_REQUIRE(TryCoerceSavedString("true", e, out));
    DS_REQUIRE(out.b == true);
    DS_REQUIRE(TryCoerceSavedString("0", e, out));
    DS_REQUIRE(out.b == false);
    DS_REQUIRE(!TryCoerceSavedString("maybe", e, out));
    printf("PASS: try_coerce_bool\n");
}

static void test_try_coerce_string_allowed() {
    OptionSchemaEntry e;
    e.key = "AngleBackend";
    e.type = ConfigValueType::String;
    e.default_value = ConfigValue::string("auto");
    e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};

    ConfigValue out;
    DS_REQUIRE(TryCoerceSavedString("vulkan", e, out));
    DS_REQUIRE(out.type == ConfigValueType::String && out.s == "vulkan");

    // Invalid membership → fail (caller keeps default).
    DS_REQUIRE(!TryCoerceSavedString("metal", e, out));

    // Wrong type helpers fail.
    DS_REQUIRE(!TryCoerceSavedBool(true, e, out));
    printf("PASS: try_coerce_string_allowed\n");
}

static void test_try_coerce_number() {
    OptionSchemaEntry e;
    e.key = "TargetRenderFPS";
    e.type = ConfigValueType::Number;
    e.default_value = ConfigValue::number(60);

    ConfigValue out;
    DS_REQUIRE(TryCoerceSavedNumber(144.0, e, out));
    DS_REQUIRE(out.type == ConfigValueType::Number && out.n == 144.0);
    DS_REQUIRE(!TryCoerceSavedString("144", e, out));
    printf("PASS: try_coerce_number\n");
}

static void test_unknown_key_ignored_pattern() {
    // Mirrors save-loop: find returns nullptr → skip without error.
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    register_business_schema_for_tests(reg);

    DS_REQUIRE(reg.find("NetworkOpt") != nullptr);
    DS_REQUIRE(reg.find("NotARealOption") == nullptr);

    // Coerce only runs when schema is found.
    const auto *sch = reg.find("NetworkOpt");
    ConfigValue out;
    DS_REQUIRE(TryCoerceSavedBool(false, *sch, out));
    DS_REQUIRE(out.b == false);
    printf("PASS: unknown_key_ignored_pattern\n");
}

static void test_effective_sources_zero_means_all() {
    using namespace ds::config;
    DS_REQUIRE(effective_sources(0) == kConfigSourceAll);
    DS_REQUIRE(source_allowed(0, ConfigSource::EnvOrCmd));
    DS_REQUIRE(source_allowed(kConfigSourceAll, ConfigSource::SaveFile));
    ConfigSourceMask save_only = static_cast<ConfigSourceMask>(ConfigSource::SaveFile);
    DS_REQUIRE(source_allowed(save_only, ConfigSource::SaveFile));
    DS_REQUIRE(!source_allowed(save_only, ConfigSource::EnvOrCmd));
    printf("PASS: effective_sources_zero_means_all\n");
}

static void test_add_same_key_different_allowed_sources_conflicts() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "AngleBackend";
    e1.type = ConfigValueType::String;
    e1.default_value = ConfigValue::string("auto");
    e1.allowed_sources = ds::config::kConfigSourceAll;
    DS_REQUIRE(reg.add(e1));

    OptionSchemaEntry e2 = e1;
    e2.allowed_sources = static_cast<ds::config::ConfigSourceMask>(
        ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault);
    // excludes LuajitConfig
    DS_REQUIRE(!reg.add(std::move(e2)));
    printf("PASS: add_same_key_different_allowed_sources_conflicts\n");
}

int main() {
    test_add_bool_find();
    test_add_same_key_same_default();
    test_add_same_key_different_default();
    test_find_missing();
    test_register_core_option_schema();
    test_register_core_vm_option_schema();
    test_l0_core_has_no_business_keys();
    test_business_schema_masks_match_plugins();
    test_try_coerce_bool();
    test_try_coerce_string_allowed();
    test_try_coerce_number();
    test_unknown_key_ignored_pattern();
    test_effective_sources_zero_means_all();
    test_add_same_key_different_allowed_sources_conflicts();

    printf("All config schema tests passed!\n");
    return 0;
}
