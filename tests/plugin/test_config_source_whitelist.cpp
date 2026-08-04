#include "config/CascadeEngine.hpp"
#include "config/ConfigSchema.hpp"
#include <cassert>
#include <cstdio>

using namespace ds::plugin;
using namespace ds::config;

static OptionSchemaEntry bool_key(const char *k, bool def, ConfigSourceMask src) {
    OptionSchemaEntry e;
    e.key = k;
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(def);
    e.allowed_sources = src;
    return e;
}

static void test_whitelist_blocks_env() {
    ConfigSchemaRegistry reg;
    // SaveFile only
    assert(reg.add(bool_key("EnableNetSim", false,
        static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
        static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault))));

    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;
    view["EnableNetSim"] = ConfigValue::boolean(false);
    prov["EnableNetSim"] = ConfigSource::ModinfoDefault;

    ConfigView save;
    save["EnableNetSim"] = ConfigValue::boolean(true);
    auto s1 = apply_partial(reg, ConfigSource::SaveFile, save, view, prov);
    assert(s1.applied == 1);
    assert(view["EnableNetSim"].b == true);
    assert(prov["EnableNetSim"] == ConfigSource::SaveFile);

    ConfigView env;
    env["EnableNetSim"] = ConfigValue::boolean(false);
    auto s2 = apply_partial(reg, ConfigSource::EnvOrCmd, env, view, prov);
    assert(s2.ignored_source == 1);
    assert(s2.applied == 0);
    assert(view["EnableNetSim"].b == true); // unchanged
    assert(prov["EnableNetSim"] == ConfigSource::SaveFile);
    printf("PASS: whitelist_blocks_env\n");
}

static void test_priority_when_all_allowed() {
    ConfigSchemaRegistry reg;
    assert(reg.add(bool_key("NetworkOpt", true, kConfigSourceAll)));
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;

    ConfigView d; d["NetworkOpt"] = ConfigValue::boolean(true);
    apply_partial(reg, ConfigSource::ModinfoDefault, d, view, prov);

    ConfigView s; s["NetworkOpt"] = ConfigValue::boolean(false);
    apply_partial(reg, ConfigSource::SaveFile, s, view, prov);
    assert(view["NetworkOpt"].b == false);

    ConfigView e; e["NetworkOpt"] = ConfigValue::boolean(true);
    apply_partial(reg, ConfigSource::EnvOrCmd, e, view, prov);
    assert(view["NetworkOpt"].b == true);
    assert(prov["NetworkOpt"] == ConfigSource::EnvOrCmd);
    printf("PASS: priority_when_all_allowed\n");
}

static void test_unknown_key_ignored() {
    ConfigSchemaRegistry reg;
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;
    ConfigView partial;
    partial["NotInSchema"] = ConfigValue::boolean(true);
    auto st = apply_partial(reg, ConfigSource::SaveFile, partial, view, prov);
    assert(st.ignored_unknown == 1);
    assert(view.count("NotInSchema") == 0);
    printf("PASS: unknown_key_ignored\n");
}

int main() {
    test_whitelist_blocks_env();
    test_priority_when_all_allowed();
    test_unknown_key_ignored();
    printf("ALL PASS: config_source_whitelist\n");
    return 0;
}
