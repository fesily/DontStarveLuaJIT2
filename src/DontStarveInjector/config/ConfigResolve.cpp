#include "CascadeEngine.hpp"
#include "sources/ConfigSources.hpp"

#include <vector>

namespace ds::config {

ResolvedConfig resolve(const ds::plugin::ConfigSchemaRegistry &schema,
                       CascadeContext ctx) {
    ModinfoDefaultSource modinfo(schema);
    LuajitConfigSource luajit;
    SaveFileSource save(schema);
    ModOverridesSource overrides(schema);
    EnvOrCmdSource env;

    std::vector<const IConfigSource *> sources;
    sources.reserve(4);
    sources.push_back(&modinfo);
    sources.push_back(&luajit);
    if (ctx.is_client) {
        sources.push_back(&save);
    } else {
        sources.push_back(&overrides);
    }
    sources.push_back(&env);
    return resolve(schema, std::move(ctx), sources);
}

} // namespace ds::config
