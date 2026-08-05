// plugin_debug_profiler — dynamic EarlyNative face of debug.profiler
// Lua face: Mod/plugins/debug_profiler.lua (profiler + GC policy; former gc.policy folded).
// Native: GameProfilerHook / Tracy / FrameGC / FullGC ownership.
// AlwaysOn native so trampolines find exports when DLL is staged; Lua gates work.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "core/PluginServices.hpp"
#include "plugins/plugin_core_vm/VmServices.hpp"
#include "plugins/plugin_core_vm/LuaEvent.hpp"
#include "config/ConfigSchema.hpp"
#include "GameProfilerHook.hpp"
#include "FullGcPolicy.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

void profiler_lua_listener(LUA_EVENT ev, lua_State *L);

struct DebugProfilerPlugin final : IPlugin {
    PluginManifest man{};

    DebugProfilerPlugin() {
        man.id = "debug.profiler";
        man.version = "1.0.0";
        // Native EarlyNative registration (sticky); Lua drives AfterModMain APIs.
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        man.soft_depends = {"core.vm"};
        man.soft_requires_services = {"ds_core_vm_get_game_lua_context", "ds_register_lua_event_listener"};
        man.priority = 20;
        // Prefer AlwaysOn native so replace_profiler / Tracy / GC exports stay
        // available whenever the DLL is staged; policy no-ops until Lua enables.
        man.options.kind = OptionRuleKind::AlwaysOn;
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &ctx) const override {
        (void) ctx;
        return true;
    }

    void load(PluginContext &ctx) override {
        // Soft DI: cache GameLuaContext when core.vm present; hot paths use cache/lookup.
        if (ds::core_vm::BindGameLuaContextService(&ctx)) {
            std::fprintf(stderr, "[plugin_debug_profiler] load debug.profiler (GameLuaContext bound)\n");
        } else {
            std::fprintf(stderr, "[plugin_debug_profiler] load debug.profiler (no core.vm service)\n");
        }
        using RegFn = bool (*)(void (*)(LUA_EVENT, lua_State *));
        auto it = ctx.services.find("ds_register_lua_event_listener");
        if (it != ctx.services.end() && it->second) {
            auto *reg = reinterpret_cast<RegFn>(it->second);
            if (reg(&profiler_lua_listener)) {
                std::fprintf(stderr, "[plugin_debug_profiler] lua_event listener registered\n");
            }
        }
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime.
    }
};

DebugProfilerPlugin g_plugin;

bool register_bool_schema(PluginHost *host, const char *key, bool default_value) {
    OptionSchemaEntry e;
    e.key = key;
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(default_value);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_debug_profiler] schema conflict %s\n", key);
        return false;
    }
    return true;
}

bool register_string_schema(PluginHost *host, const char *key, const char *default_value,
                            std::initializer_list<const char *> allowed) {
    OptionSchemaEntry e;
    e.key = key;
    e.type = ConfigValueType::String;
    e.default_value = ConfigValue::string(default_value);
    for (const char *opt : allowed) {
        e.allowed.emplace_back(opt);
    }
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_debug_profiler] schema conflict %s\n", key);
        return false;
    }
    return true;
}

// Bridge typed LUA_EVENT bus → existing profiler notifyer export.
void profiler_lua_listener(LUA_EVENT ev, lua_State *L) {
    DS_LUAJIT_profiler_lua_event_notifyer(static_cast<int>(ev), L);
}

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    // Schema matches modinfo defaults; cascade/L0 may re-register same entries later.
    if (!register_string_schema(host, "EnableProfiler", "off", {"off", "fzvp", "Gz"})) {
        return false;
    }
    if (!register_string_schema(host, "EnableTracy", "off", {"off", "on"})) {
        return false;
    }
    if (!register_bool_schema(host, "DisableForceFullGC", true)) {
        return false;
    }
    if (!register_bool_schema(host, "EnableFrameGC", true)) {
        return false;
    }

    // Host service table + lua_event bus — no L0 hardcode of this DLL.
    // Declarations come from FullGcPolicy.hpp / GameProfilerHook.hpp / ProfilerApi.cpp.
        // core.vm gameio forwards fullgc here (typed service).
    (void) host->register_service(
        "lj_gc_fullgc_external",
        {ds::plugin::GiType::Void, ds::plugin::GiType::LightUserdata, ds::plugin::GiType::LightUserdata},
        reinterpret_cast<void *>(&lj_gc_fullgc_external));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_disable_fullgc",
        {ds::plugin::GiType::Void, ds::plugin::GiType::Bool},
        reinterpret_cast<void *>(&DS_LUAJIT_disable_fullgc));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_replace_profiler_api",
        {ds::plugin::GiType::I32},
        reinterpret_cast<void *>(&DS_LUAJIT_replace_profiler_api));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_enable_tracy",
        {ds::plugin::GiType::Void, ds::plugin::GiType::I32},
        reinterpret_cast<void *>(&DS_LUAJIT_enable_tracy));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_enable_framegc",
        {ds::plugin::GiType::Bool, ds::plugin::GiType::Bool},
        reinterpret_cast<void *>(&DS_LUAJIT_enable_framegc));
    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_debug_profiler] module init registered debug.profiler\n");
    return true;
}
