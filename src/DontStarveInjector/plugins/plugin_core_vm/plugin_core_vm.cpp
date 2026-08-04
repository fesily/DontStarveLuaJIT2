// plugin_core_vm — optional core.vm module (V-S1 stub).
// Signature + ReplaceLuaModule still live in Injector; this module only registers
// id core.vm and exports ds_core_vm_run_signature_and_replace returning false so
// CoreVmBootstrap falls back to LegacySignatureAndReplaceInInjector until Task 3.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/CoreVmBootstrap.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct CoreVmPlugin final : IPlugin {
    PluginManifest man{};

    CoreVmPlugin() {
        man.id = "core.vm";
        man.version = "0.1.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // High priority (low number): native VM face before feature plugins.
        man.priority = 10;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override { return true; }

    void load(PluginContext &) override {
        // V-S1: no eager work — real signature/replace moves in later tasks.
        std::fprintf(stderr, "[plugin_core_vm] core.vm EarlyNative load (stub)\n");
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime.
    }
};

CoreVmPlugin g_core_vm;

} // namespace

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    host->register_plugin(&g_core_vm);
    std::fprintf(stderr, "[plugin_core_vm] module init registered core.vm\n");
    return true;
}

// Optional C bootstrap export. Stub returns false so L0 uses legacy path (V-S1).
DS_PLUGIN_MODULE_EXPORT bool ds_core_vm_run_signature_and_replace(const ds::core_vm::BootstrapArgs *args) {
    (void) args;
    std::fprintf(stderr,
                 "[plugin_core_vm] ds_core_vm_run_signature_and_replace stub — "
                 "implementation still in Injector\n");
    return false;
}
