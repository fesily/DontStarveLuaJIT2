#include "core/ConfigSchema.hpp"

#include <cassert>
#include <cstdio>

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

int main() {
    test_add_bool_find();
    test_add_same_key_same_default();
    test_add_same_key_different_default();
    test_find_missing();
    printf("All config schema tests passed!\n");
    return 0;
}
