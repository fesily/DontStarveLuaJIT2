// plugin_debug_profiler — dynamic EarlyNative face of debug.profiler
// Lua face: Mod/plugins/debug_profiler.lua (profiler + GC policy; former gc.policy folded).
// Native: GameProfilerHook / Tracy / FrameGC / FullGC ownership.
// AlwaysOn native so trampolines find exports when DLL is staged; Lua gates work.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/PluginServices.hpp"
#include "core/LuaEvent.hpp"
#include "core/ConfigSchema.hpp"
#include "GameProfilerHook.hpp"
#include "FullGcPolicy.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct DebugProfilerPlugin final : IPlugin {
    PluginManifest man{};

    DebugProfilerPlugin() {
        man.id = "debug.profiler";
        man.version = "1.0.0";
        // Native EarlyNative registration (sticky); Lua drives AfterModMain APIs.
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
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

    void load(PluginContext &) override {
        std::fprintf(stderr, "[plugin_debug_profiler] load debug.profiler\n");
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
    ds_host_register_service("lj_gc_fullgc_external",
                             reinterpret_cast<void *>(&lj_gc_fullgc_external));
    ds_host_register_service("DS_LUAJIT_disable_fullgc",
                             reinterpret_cast<void *>(&DS_LUAJIT_disable_fullgc));
    ds_host_register_service("DS_LUAJIT_replace_profiler_api",
                             reinterpret_cast<void *>(&DS_LUAJIT_replace_profiler_api));
    ds_host_register_service("DS_LUAJIT_enable_tracy",
                             reinterpret_cast<void *>(&DS_LUAJIT_enable_tracy));
    ds_host_register_service("DS_LUAJIT_enable_framegc",
                             reinterpret_cast<void *>(&DS_LUAJIT_enable_framegc));
    (void) ds_register_lua_event_listener(&profiler_lua_listener);

    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_debug_profiler] module init registered debug.profiler\n");
    return true;
}
