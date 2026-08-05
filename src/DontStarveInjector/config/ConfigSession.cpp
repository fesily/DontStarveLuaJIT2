#include "config.hpp"  // InjectorCtx, MOD_VERSION
#include "config/ConfigSession.hpp"
#include "gameModConfig.hpp"
#include "config/write/SaveConfigWriter.hpp"
#include "game_info.hpp"
#include "config/sources/LuajitConfigFile.hpp"
#include "config/CascadeEngine.hpp"
#include "config/Compat.hpp"
#include "config/path/ConfigPaths.hpp"
#include "config/ConfigSchema.hpp"

#include <optional>
#include <spdlog/spdlog.h>
#include <string>

namespace {

// Mutable production cascade schema: L0 core first; plugins append VM/business
// keys during DynamicPluginLoader module_init. Full resolve must run after that
// merge so save/env values are not dropped as unknown (OB-S2 / OB-S4).
ds::plugin::ConfigSchemaRegistry &cascade_option_schema() {
    static ds::plugin::ConfigSchemaRegistry schema = [] {
        ds::plugin::ConfigSchemaRegistry r;
        ds::plugin::RegisterCoreOptionSchema(r);
        return r;
    }();
    return schema;
}

static std::optional<ds::config::ResolvedConfig> g_resolved_config;
static std::optional<GameJitModConfig> g_game_jit_mod_config;

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

static std::optional<GameJitModConfig> load_resolved_game_mod_config() {
    auto ctx = build_cascade_context();
    g_resolved_config = ds::config::resolve(cascade_option_schema(), ctx);
    auto resolved = ds::config::map_to_game_jit_mod_config(*g_resolved_config);

    if (ctx.is_client && resolved.save_file && !resolved.save_file->empty()) {
        WriteGameJitModConfigToSaveFile(*resolved.save_file, resolved);
    }

    return resolved;
}

} // namespace

namespace ds::config {

DS_INJECTOR_CXX_API const ResolvedConfig *current() {
    return g_resolved_config ? &*g_resolved_config : nullptr;
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
    auto mapped = map_to_game_jit_mod_config(*g_resolved_config);
    if (ctx.is_client && mapped.save_file && !mapped.save_file->empty()) {
        WriteGameJitModConfigToSaveFile(*mapped.save_file, mapped);
    }
    g_game_jit_mod_config = std::move(mapped);
}

} // namespace ds::config

std::optional<GameJitModConfig> GameJitModConfig::instance() {
    if (g_game_jit_mod_config) {
        return g_game_jit_mod_config;
    }
    static std::optional<GameJitModConfig> early = load_resolved_game_mod_config();
    if (!g_game_jit_mod_config && early) {
        g_game_jit_mod_config = early;
    }
    return g_game_jit_mod_config;
}

