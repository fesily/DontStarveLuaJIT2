#include "RegisterBuiltinPlugins.hpp"
#include "PluginHost.hpp"
#include "PluginTypes.hpp"

#include "GameNetwork.hpp"
#include "GameOpenGl.hpp"

// Declared by GameRenderHook (Win) / stubbed by GameLuaModule (non-Win).
// DONTSTARVEINJECTOR_GAME_API exports as extern "C".
extern "C" void DS_LUAJIT_set_vbpool_enabled(bool enable);

namespace ds::plugin {
namespace {

// Native EarlyNative face of dual-face plugin network.rpc.
// Lua face (AfterModMain) lives in Mod/plugins/network_rpc.lua under the same id.
struct NetworkRpcPlugin final : IPlugin {
    PluginManifest man{};

    NetworkRpcPlugin() {
        man.id = "network.rpc";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.priority = 40;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"NetworkOpt"};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override { return true; }

    void load(PluginContext &) override {
        // Installs RPC4 SetNextRpcInfo probe + entity serialize channel hooks.
        // Entity Lua face (network.entity) hard-depends on this plugin so the
        // serialize hooks are present whenever entity opt is allowed to load.
        GameNetWorkHookRpc4();
    }

    void unload(PluginContext &) override {
        // Sticky by default; gum probes are not torn down.
    }
};

// EarlyNative: enable HWBuffer GL-name pool before first buffer create.
// Option: EnableVBPool. Client + Win only (hooks live in GameRenderHook).
struct RenderVbpoolPlugin final : IPlugin {
    PluginManifest man{};

    RenderVbpoolPlugin() {
        man.id = "render.vbpool";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Before network.rpc; matches former LoadGameModConfig order (vbpool then angle).
        man.priority = 20;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {"EnableVBPool"};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        return ctx.is_client;
#else
        (void) ctx;
        return false;
#endif
    }

    void load(PluginContext &) override {
        DS_LUAJIT_set_vbpool_enabled(true);
    }

    void unload(PluginContext &) override {
        // Sticky; pool hooks stay for process lifetime unless disabled via API.
    }
};

// EarlyNative: ANGLE backend rebind / InitGameOpenGl.
// Always option-enabled; AngleBackend is a *parameter* (auto no-ops inside InitGameOpenGl).
// Win client only.
struct RenderAnglePlugin final : IPlugin {
    PluginManifest man{};

    RenderAnglePlugin() {
        man.id = "render.angle";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // After vbpool in former LoadGameModConfig sequence.
        man.priority = 30;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
#ifdef _WIN32
        return ctx.is_client;
#else
        (void) ctx;
        return false;
#endif
    }

    void load(PluginContext &ctx) override {
        // Backend string is already in ConfigView / GameJitModConfig; InitGameOpenGl
        // reads the resolved singleton (same cascade the bridge mirrors).
        (void) ctx;
        InitGameOpenGl();
    }

    void unload(PluginContext &) override {
        // Sticky ANGLE IAT rebind.
    }
};

NetworkRpcPlugin g_network_rpc;
RenderVbpoolPlugin g_render_vbpool;
RenderAnglePlugin g_render_angle;

} // namespace

void RegisterBuiltinPlugins(PluginHost &host) {
    host.register_plugin(&g_network_rpc);
    host.register_plugin(&g_render_vbpool);
    host.register_plugin(&g_render_angle);
}

} // namespace ds::plugin
