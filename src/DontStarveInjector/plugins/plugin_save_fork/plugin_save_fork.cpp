// plugin_save_fork — dynamic EarlyNative face of save.fork
// Lua face: Mod/plugins/save_fork.lua (AfterModMain, EnableForkSave).
// Native APIs: DS_LUAJIT_fork_save / exit / cleanup / wait / poll.
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/GameInjectorLuaBind.hpp"
#include "core/PluginTypes.hpp"
#include "config/ConfigSource.hpp"
#include "ForkSaveOptionKeys.hpp"

#include "core/PluginServices.hpp"

#include <cstdio>

namespace {

using namespace ds::plugin;

struct SaveForkPlugin final : IPlugin {
    PluginManifest man{};

    SaveForkPlugin() {
        man.id = "save.fork";
        man.version = "1.0.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // Inventory priority 60 (with network.sim / lagcomp).
        // Host resolve skips load() when EnableForkSave is false; DLL stays mapped
        // so GameInjector can resolve fork APIs via host service table when Lua enables.
        man.priority = 60;
        man.options.kind = OptionRuleKind::AllOf;
        man.options.keys = {std::string{ds::config::keys::kEnableForkSave}};
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override {
        // Native fork/clone is implemented for Win x64 + Linux (+ mac stubs in TU).
        return true;
    }

    void load(PluginContext &) override {
        // No eager hooks — APIs are called from Lua scripts/fork_save.lua.
        std::fprintf(stderr, "[plugin_save_fork] native fork_save APIs ready\n");
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime.
    }
};

SaveForkPlugin g_save_fork;

} // namespace

extern "C" const char *DS_LUAJIT_fork_save();
extern "C" void DS_LUAJIT_fork_save_exit();
extern "C" void DS_LUAJIT_fork_save_cleanup();
extern "C" void DS_LUAJIT_fork_save_wait();
extern "C" const char *DS_LUAJIT_fork_save_poll();

DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version() {
    return DS_PLUGIN_ABI_VERSION;
}

DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host) {
    if (!host) {
        return false;
    }
    OptionSchemaEntry e;
    e.key = std::string{ds::config::keys::kEnableForkSave};
    e.type = ConfigValueType::Bool;
    e.default_value = ConfigValue::boolean(true);
    e.allowed_sources =
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::ModinfoDefault) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::SaveFile) |
        static_cast<ds::config::ConfigSourceMask>(ds::config::ConfigSource::EnvOrCmd);
    if (!host->register_option_schema(std::move(e))) {
        std::fprintf(stderr, "[plugin_save_fork] schema conflict %s\n",
                     std::string{ds::config::keys::kEnableForkSave}.c_str());
        return false;
    }

        (void) host->register_game_injector_export(
        "DS_LUAJIT_fork_save",
        {ds::plugin::GiType::CString},
        reinterpret_cast<void *>(&DS_LUAJIT_fork_save));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_fork_save_exit",
        {ds::plugin::GiType::Void},
        reinterpret_cast<void *>(&DS_LUAJIT_fork_save_exit));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_fork_save_cleanup",
        {ds::plugin::GiType::Void},
        reinterpret_cast<void *>(&DS_LUAJIT_fork_save_cleanup));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_fork_save_wait",
        {ds::plugin::GiType::Void},
        reinterpret_cast<void *>(&DS_LUAJIT_fork_save_wait));
    (void) host->register_game_injector_export(
        "DS_LUAJIT_fork_save_poll",
        {ds::plugin::GiType::CString},
        reinterpret_cast<void *>(&DS_LUAJIT_fork_save_poll));
    host->register_plugin(&g_save_fork);
    std::fprintf(stderr, "[plugin_save_fork] module init registered save.fork\n");
    return true;
}
