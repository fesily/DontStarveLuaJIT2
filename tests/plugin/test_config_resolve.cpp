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

} // namespace

int main() {
    test_resolve_respects_source_order_and_whitelist();
    test_resolve_empty_sources_yields_empty_view();
    printf("ALL PASS: config_resolve\n");
    return 0;
}
