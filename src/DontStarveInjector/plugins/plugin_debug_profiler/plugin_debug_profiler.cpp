// plugin_debug_profiler — dynamic EarlyNative face of debug.profiler
// Lua face (later): Mod/plugins/debug_profiler.lua (+ gc.policy fold).
// Native: GameProfilerHook / Tracy / FrameGC / FullGC (Task 3).
// AlwaysOn native so trampolines find exports when DLL is staged; Lua gates work.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/ConfigSchema.hpp"

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
    host->register_plugin(&g_plugin);
    std::fprintf(stderr, "[plugin_debug_profiler] module init registered debug.profiler\n");
    return true;
}
