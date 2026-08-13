// plugin_client_anim — EarlyNative face of client.anim
// Lua face: modinfo + modmain + scripts/client_anim.lua
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "ClientAnimOptionKeys.hpp"
#include "ClientAnimHooks.hpp"

#include "core/PluginServices.hpp"
#include "plugins/plugin_core_vm/VmServices.hpp"

#include <cstdio>
#include <stdexcept>

struct lua_State;

namespace {

using namespace ds::plugin;

// Mirror lagcomp UnwrapEntity (entity userdata → cEntity*).
static char *UnwrapEntity(void *ud) {
    if (!ud) return nullptr;
    char *proxy = *reinterpret_cast<char **>(ud);
    if (!proxy) return nullptr;
    return *reinterpret_cast<char **>(proxy);
}

struct ClientAnimPlugin final : IPlugin {
    PluginManifest man{};

    ClientAnimPlugin() {
        man.id = "client.anim";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.depends = {"core.vm"};
        man.requires_services = {"ds_core_vm_get_game_lua_context"};
        man.priority = 55;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kEnableClientAnimOwn}};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        // Client process only (pred-OFF visual path).
        return ctx.is_client;
#else
        (void)ctx;
        return false;
#endif
    }

    void load(PluginContext &ctx) override {
        if (!ds::core_vm::BindGameLuaContextService(&ctx)) {
            throw std::runtime_error("client.anim: missing ds_core_vm_get_game_lua_context");
        }
        if (!client_anim_install_hooks()) {
            std::fprintf(stderr, "[client.anim] hook install failed (feature inactive)\n");
            return;
        }
        std::fprintf(stderr, "[client.anim] native ready\n");
    }

    void unload(PluginContext &) override {
        client_anim_set_own(false);
        client_anim_set_local_player_entity(nullptr);
    }
};

ClientAnimPlugin g_client_anim;

} // namespace

// Lua 5.1: bind ThePlayer.entity userdata → local player for local_a0 gate.
extern "C" int DS_LUAJIT_client_anim_bind_player(lua_State *L) {
    auto *ctx = ds::core_vm::TryGetGameLuaContext();
    if (!ctx) return 0;
    auto &api = ctx->api;
    const int ty = api._lua_type(L, 1);
    char *ent = nullptr;
    if (ty == 2 /* LUA_TLIGHTUSERDATA */) {
        ent = static_cast<char *>(api._lua_touserdata(L, 1));
    } else if (ty == 7 /* LUA_TUSERDATA */) {
        ent = UnwrapEntity(api._lua_touserdata(L, 1));
    }
    client_anim_set_local_player_entity(ent);
    api._lua_pushboolean(L, ent ? 1 : 0);
    return 1;
}

extern "C" void DS_LUAJIT_client_anim_set_own(bool on) {
    client_anim_set_own(on);
}
extern "C" int DS_LUAJIT_client_anim_get_own() {
    return client_anim_get_own() ? 1 : 0;
}
extern "C" int DS_LUAJIT_client_anim_is_installed() {
    return client_anim_is_installed() ? 1 : 0;
}
extern "C" int DS_LUAJIT_client_anim_enter_count() {
    return client_anim_enter_count();
}
extern "C" int DS_LUAJIT_client_anim_match_count() {
    return client_anim_match_count();
}

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) return false;

    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kEnableClientAnimOwn};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(true);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[client.anim] schema conflict %s\n",
                     std::string{ds::config::keys::kEnableClientAnimOwn}.c_str());
        return false;
    }

    (void)host->register_game_injector_export("DS_LUAJIT_client_anim_bind_player",
                                              &DS_LUAJIT_client_anim_bind_player);
    (void)host->register_game_injector_export("DS_LUAJIT_client_anim_set_own",
                                              &DS_LUAJIT_client_anim_set_own);
    (void)host->register_game_injector_export("DS_LUAJIT_client_anim_get_own",
                                              &DS_LUAJIT_client_anim_get_own);
    (void)host->register_game_injector_export("DS_LUAJIT_client_anim_is_installed",
                                              &DS_LUAJIT_client_anim_is_installed);
    (void)host->register_game_injector_export("DS_LUAJIT_client_anim_enter_count",
                                              &DS_LUAJIT_client_anim_enter_count);
    (void)host->register_game_injector_export("DS_LUAJIT_client_anim_match_count",
                                              &DS_LUAJIT_client_anim_match_count);

    host->register_plugin(&g_client_anim);
    std::fprintf(stderr, "[plugin_client_anim] module init registered client.anim\n");
    return true;
}
