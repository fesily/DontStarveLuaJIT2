#include "config/CascadeEngine.hpp"
#include "config/ConfigSchema.hpp"
#include <doctest/doctest.h>

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

TEST_CASE("test_config_source_whitelist/whitelist_blocks_env") {
    ConfigSchemaRegistry reg;
    // SaveFile only
    REQUIRE(reg.add(bool_key("EnableNetSim", false,
        static_cast<ConfigSourceMask>(ConfigSource::SaveFile) |
        static_cast<ConfigSourceMask>(ConfigSource::ModinfoDefault))));

    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;
    view["EnableNetSim"] = ConfigValue::boolean(false);
    prov["EnableNetSim"] = ConfigSource::ModinfoDefault;

    ConfigView save;
    save["EnableNetSim"] = ConfigValue::boolean(true);
    auto s1 = apply_partial(reg, ConfigSource::SaveFile, save, view, prov);
    REQUIRE_EQ(s1.applied, 1);
    REQUIRE_EQ(view["EnableNetSim"].b, true);
    REQUIRE_EQ(prov["EnableNetSim"], ConfigSource::SaveFile);

    ConfigView env;
    env["EnableNetSim"] = ConfigValue::boolean(false);
    auto s2 = apply_partial(reg, ConfigSource::EnvOrCmd, env, view, prov);
    REQUIRE_EQ(s2.ignored_source, 1);
    REQUIRE_EQ(s2.applied, 0);
    REQUIRE_EQ(view["EnableNetSim"].b, true); // unchanged
    REQUIRE_EQ(prov["EnableNetSim"], ConfigSource::SaveFile);
}

TEST_CASE("test_config_source_whitelist/priority_when_all_allowed") {
    ConfigSchemaRegistry reg;
    REQUIRE(reg.add(bool_key("NetworkOpt", true, kConfigSourceAll)));
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;

    ConfigView d; d["NetworkOpt"] = ConfigValue::boolean(true);
    apply_partial(reg, ConfigSource::ModinfoDefault, d, view, prov);

    ConfigView s; s["NetworkOpt"] = ConfigValue::boolean(false);
    apply_partial(reg, ConfigSource::SaveFile, s, view, prov);
    REQUIRE_EQ(view["NetworkOpt"].b, false);

    ConfigView e; e["NetworkOpt"] = ConfigValue::boolean(true);
    apply_partial(reg, ConfigSource::EnvOrCmd, e, view, prov);
    REQUIRE_EQ(view["NetworkOpt"].b, true);
    REQUIRE_EQ(prov["NetworkOpt"], ConfigSource::EnvOrCmd);
}

TEST_CASE("test_config_source_whitelist/unknown_key_ignored") {
    ConfigSchemaRegistry reg;
    ConfigView view;
    std::unordered_map<std::string, ConfigSource> prov;
    ConfigView partial;
    partial["NotInSchema"] = ConfigValue::boolean(true);
    auto st = apply_partial(reg, ConfigSource::SaveFile, partial, view, prov);
    REQUIRE_EQ(st.ignored_unknown, 1);
    REQUIRE_EQ(view.count("NotInSchema"), 0);
}
