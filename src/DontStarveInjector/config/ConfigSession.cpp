#include "config/InjectorHostConfig.hpp"
#include "config/ConfigSession.hpp"
#include "game_info.hpp"
#include "config/sources/LuajitConfigFile.hpp"
#include "config/CascadeEngine.hpp"
#include "config/path/ConfigPaths.hpp"
#include "config/ConfigSchema.hpp"

#include <optional>
#include <spdlog/spdlog.h>
#include <string>

namespace {

ds::plugin::ConfigSchemaRegistry &cascade_option_schema() {
    static ds::plugin::ConfigSchemaRegistry schema = [] {
        ds::plugin::ConfigSchemaRegistry r;
        ds::plugin::RegisterCoreOptionSchema(r);
        return r;
    }();
    return schema;
}

static std::optional<ds::config::ResolvedConfig> g_resolved_config;

static ds::config::CascadeContext build_cascade_context() {
    auto *ictx = InjectorCtx::instance();
    ds::config::CascadeContext ctx;
    ctx.is_client = ictx->DontStarveInjectorIsClient;
    ctx.steam_account_id = ictx->steam_account_id;

    const auto identity = ds::config::path::build_mod_identity();
    ctx.modname = identity.modname;
    ctx.modid = identity.modid;
    ctx.aliases = identity.aliases;
    if (const auto cfg = luajit_config::read_from_file(); cfg && !cfg->modmain_path.empty()) {
        ctx.modmain_path = cfg->modmain_path;
    }

    if (!ctx.is_client) {
        const auto ownerdir_value = ds::config::path::read_env_or_cmd_value("ownerdir");
        if (!ownerdir_value.empty()) {
            ctx.ownerdir_hint = ownerdir_value;
        } else if (ictx->steam_account_id != 0) {
            ctx.ownerdir_hint = std::to_string(ictx->steam_account_id);
        }
    }
    return ctx;
}

static void resolve_session() {
    auto ctx = build_cascade_context();
    g_resolved_config = ds::config::resolve(cascade_option_schema(), ctx);
}

} // namespace

namespace ds::config {

DS_INJECTOR_CXX_API const ResolvedConfig *current() {
    return g_resolved_config ? &*g_resolved_config : nullptr;
}

// Ensure cascade has run at least once (early bootstrap). Prefer refresh after plugins.
DS_INJECTOR_CXX_API const ResolvedConfig *ensure_resolved() {
    if (!g_resolved_config) {
        resolve_session();
    }
    return current();
}

DS_INJECTOR_CXX_API void refresh_cascade_after_plugins(
    const ds::plugin::ConfigSchemaRegistry &host_schema) {
    auto &cascade = cascade_option_schema();
    for (const auto *e : host_schema.all()) {
        if (e == nullptr) {
            continue;
        }
        (void) cascade.add(*e);
    }
    auto ctx = build_cascade_context();
    g_resolved_config = ds::config::resolve(cascade, ctx);
}

} // namespace ds::config
