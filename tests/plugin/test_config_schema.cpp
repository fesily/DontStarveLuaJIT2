#include "core/ConfigSchema.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include "config/ConfigSource.hpp"


using namespace ds::plugin;

static void test_add_bool_find() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);
    assert(reg.add(std::move(e)));
    assert(reg.size() == 1);

    const auto *found = reg.find("EnableVBPool");
    assert(found != nullptr);
    assert(found->key == "EnableVBPool");
    assert(found->type == ConfigValueType::Bool);
    assert(found->default_value.type == ConfigValueType::Bool);
    assert(found->default_value.b == false);
    printf("PASS: add_bool_find\n");
}

static void test_add_same_key_same_default() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "EnableVBPool";
    e1.type = ConfigValueType::Bool;
    e1.default_value = ConfigValue::boolean(false);
    assert(reg.add(std::move(e1)));

    OptionSchemaEntry e2;
    e2.key = "EnableVBPool";
    e2.type = ConfigValueType::Bool;
    e2.default_value = ConfigValue::boolean(false);
    assert(reg.add(std::move(e2)));
    assert(reg.size() == 1);
    printf("PASS: add_same_key_same_default\n");
}

static void test_add_same_key_different_default() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "EnableVBPool";
    e1.type = ConfigValueType::Bool;
    e1.default_value = ConfigValue::boolean(false);
    assert(reg.add(std::move(e1)));

    OptionSchemaEntry e2;
    e2.key = "EnableVBPool";
    e2.type = ConfigValueType::Bool;
    e2.default_value = ConfigValue::boolean(true);
    assert(!reg.add(std::move(e2)));
    assert(reg.size() == 1);

    const auto *found = reg.find("EnableVBPool");
    assert(found != nullptr);
    assert(found->default_value.b == false);
    printf("PASS: add_same_key_different_default\n");
}

static void test_find_missing() {
    ConfigSchemaRegistry reg;
    assert(reg.find("MissingKey") == nullptr);
    printf("PASS: find_missing\n");
}

static void test_register_core_option_schema() {
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    assert(reg.size() == 4);
    assert(reg.find("AlwaysEnableMod") != nullptr);
    assert(reg.find("DisableJITWhenServer") != nullptr);
    assert(reg.find("LuaVmType") != nullptr);
    assert(reg.find("EnabledGenGC") != nullptr);

    const auto *lua_vm = reg.find("LuaVmType");
    assert(lua_vm->type == ConfigValueType::String);
    assert(lua_vm->default_value.s == "jit");
    assert(!lua_vm->allowed.empty());
    // Env/cmd historical aliases must be schema-allowed so apply_partial accepts them.
    auto has_allowed = [&](const char *v) {
        return std::find(lua_vm->allowed.begin(), lua_vm->allowed.end(), v) !=
               lua_vm->allowed.end();
    };
    assert(has_allowed("jit"));
    assert(has_allowed("game"));
    assert(has_allowed("lua51"));
    assert(has_allowed("51"));
    assert(has_allowed("5.1"));
    assert(has_allowed("_51"));
    assert(has_allowed("jit_gen"));

    // Idempotent re-register.
    RegisterCoreOptionSchema(reg);
    assert(reg.size() == 4);
    printf("PASS: register_core_option_schema\n");
}

static void test_register_builtin_business_schema() {
    ConfigSchemaRegistry reg;
    RegisterBuiltinBusinessOptionSchema(reg);
    assert(reg.find("AngleBackend") != nullptr);
    assert(reg.find("EnableVBPool") != nullptr);
    assert(reg.find("NetworkOpt") != nullptr);
    assert(reg.find("EnableNetSim") != nullptr);

    const auto *angle = reg.find("AngleBackend");
    assert(angle->type == ConfigValueType::String);
    assert(angle->default_value.s == "auto");
    assert(angle->allowed.size() == 4);

    // Unknown key still missing — parse loop ignores unknowns.
    assert(reg.find("TotallyUnknownOption") == nullptr);
    printf("PASS: register_builtin_business_schema\n");
}

static void test_try_coerce_bool() {
    OptionSchemaEntry e;
    e.key = "EnableVBPool";
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(false);

    ConfigValue out;
    assert(TryCoerceSavedBool(true, e, out));
    assert(out.type == ConfigValueType::Bool && out.b == true);

    assert(TryCoerceSavedNumber(1.0, e, out));
    assert(out.type == ConfigValueType::Bool && out.b == true);
    assert(TryCoerceSavedNumber(0.0, e, out));
    assert(out.type == ConfigValueType::Bool && out.b == false);

    assert(TryCoerceSavedString("true", e, out));
    assert(out.b == true);
    assert(TryCoerceSavedString("0", e, out));
    assert(out.b == false);
    assert(!TryCoerceSavedString("maybe", e, out));
    printf("PASS: try_coerce_bool\n");
}

static void test_try_coerce_string_allowed() {
    OptionSchemaEntry e;
    e.key = "AngleBackend";
    e.type = ConfigValueType::String;
    e.default_value = ConfigValue::string("auto");
    e.allowed = {"auto", "vulkan", "d3d11", "d3d9"};

    ConfigValue out;
    assert(TryCoerceSavedString("vulkan", e, out));
    assert(out.type == ConfigValueType::String && out.s == "vulkan");

    // Invalid membership → fail (caller keeps default).
    assert(!TryCoerceSavedString("metal", e, out));

    // Wrong type helpers fail.
    assert(!TryCoerceSavedBool(true, e, out));
    printf("PASS: try_coerce_string_allowed\n");
}

static void test_try_coerce_number() {
    OptionSchemaEntry e;
    e.key = "TargetRenderFPS";
    e.type = ConfigValueType::Number;
    e.default_value = ConfigValue::number(60);

    ConfigValue out;
    assert(TryCoerceSavedNumber(144.0, e, out));
    assert(out.type == ConfigValueType::Number && out.n == 144.0);
    assert(!TryCoerceSavedString("144", e, out));
    printf("PASS: try_coerce_number\n");
}

static void test_unknown_key_ignored_pattern() {
    // Mirrors save-loop: find returns nullptr → skip without error.
    ConfigSchemaRegistry reg;
    RegisterCoreOptionSchema(reg);
    RegisterBuiltinBusinessOptionSchema(reg);

    assert(reg.find("NetworkOpt") != nullptr);
    assert(reg.find("NotARealOption") == nullptr);

    // Coerce only runs when schema is found.
    const auto *sch = reg.find("NetworkOpt");
    ConfigValue out;
    assert(TryCoerceSavedBool(false, *sch, out));
    assert(out.b == false);
    printf("PASS: unknown_key_ignored_pattern\n");
}

static void test_effective_sources_zero_means_all() {
    using namespace ds::config;
    assert(effective_sources(0) == kConfigSourceAll);
    assert(source_allowed(0, ConfigSource::EnvOrCmd));
    assert(source_allowed(kConfigSourceAll, ConfigSource::SaveFile));
    ConfigSourceMask save_only = static_cast<ConfigSourceMask>(ConfigSource::SaveFile);
    assert(source_allowed(save_only, ConfigSource::SaveFile));
    assert(!source_allowed(save_only, ConfigSource::EnvOrCmd));
    printf("PASS: effective_sources_zero_means_all\n");
}

static void test_add_same_key_different_allowed_sources_conflicts() {
    ConfigSchemaRegistry reg;
    OptionSchemaEntry e1;
    e1.key = "AngleBackend";
    e1.type = ConfigValueType::String;
    e1.default_value = ConfigValue::string("auto");
    e1.allowed_sources = ds::config::kConfigSourceAll;
    assert(reg.add(e1));

    OptionSchemaEntry e2 = e1;
    e2.allowed_sources = static_cast<ds::config::ConfigSourceMask>(
        ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault);
    // excludes LuajitConfig
    assert(!reg.add(std::move(e2)));
    printf("PASS: add_same_key_different_allowed_sources_conflicts\n");
}

int main() {
    test_add_bool_find();
    test_add_same_key_same_default();
    test_add_same_key_different_default();
    test_find_missing();
    test_register_core_option_schema();
    test_register_builtin_business_schema();
    test_try_coerce_bool();
    test_try_coerce_string_allowed();
    test_try_coerce_number();
    test_unknown_key_ignored_pattern();
    test_effective_sources_zero_means_all();
    test_add_same_key_different_allowed_sources_conflicts();

    printf("All config schema tests passed!\n");
    return 0;
}
