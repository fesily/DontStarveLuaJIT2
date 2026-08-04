// plugin_core_vm — optional core.vm module (V-S2+V-S3).
// Owns Signature + ReplaceLuaModule. L0 calls ds_core_vm_run_signature_and_replace
// when the module is present; missing module is a soft skip (no legacy fallback).
#include "core/PluginModuleAbi.hpp"
#include "core/PluginHost.hpp"
#include "core/PluginTypes.hpp"
#include "core/CoreVmBootstrap.hpp"

#include "GameLua.hpp"
#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include "ProcessMutex.hpp"
#include "config.hpp"
#include "util/platform.hpp"
#include "util/tools.hpp"
#include "ctx.hpp"
#include "ModuleSections.hpp"
#include "disasm.h"
#include "MemorySignature.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

#include <spdlog/spdlog.h>
#include <frida-gum.h>

#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <Windows.h>
#endif

namespace {

using namespace ds::plugin;

// Mirror of Injector showError — hard fail for signature path when VM module is active.
[[noreturn]] void showError(const std::string_view &msg) {
#ifdef _WIN32
    MessageBoxA(NULL, msg.data(), "error!", 0);
#else
    spdlog::error("error: {}", msg);
#endif
    std::exit(1);
}

// Dev branch patch lives with the VM path (was replace_game_branch_flag_to_dev in Injector).
#ifdef _WIN32
using GetBuildTypeFn = const char *(*)(void *self);
GetBuildTypeFn original_get_build_type = nullptr;

const char *forced_get_build_type(void *self) {
    (void) self;
    return "dev";
}

uintptr_t find_build_type_function(const function_relocation::ModuleSections &module_main) {
    function_relocation::MemorySignature build_type_signature{"48 8B 05 ?? ?? ?? ?? C3", 0};
    build_type_signature.only_one = false;
    build_type_signature.log = false;
    build_type_signature.prot_flag = GUM_PAGE_EXECUTE;
    if (!build_type_signature.scan(module_main.text.base_address, module_main.text.size)) {
        return 0;
    }

    for (const auto candidate : build_type_signature.targets) {
        auto insn = function_relocation::disasm::get_insn(reinterpret_cast<void *>(candidate), 8);
        if (!insn || insn->detail->x86.op_count != 2) {
            continue;
        }

        const auto &x86 = insn->detail->x86;
        if (x86.operands[0].type != X86_OP_REG || x86.operands[1].type != X86_OP_MEM) {
            continue;
        }

        const auto string_ptr_address = function_relocation::read_operand_rip_mem(*insn, x86.operands[1]);
        if (!string_ptr_address || !module_main.in_rodata(*reinterpret_cast<uintptr_t *>(string_ptr_address))) {
            continue;
        }

        const auto build_type = reinterpret_cast<const char *>(*reinterpret_cast<uintptr_t *>(string_ptr_address));
        if (build_type && std::string_view{build_type} == "release") {
            return candidate;
        }
    }

    return 0;
}
#endif

void replace_game_branch_flag_to_dev(const std::string &mainPath) {
#ifdef _WIN32
    if (!InjectorConfig::instance()->AppVersionDevPatch) {
        return;
    }

    static bool patched = false;
    if (patched) {
        return;
    }

    function_relocation::ModuleSections moduleMain{};
    if (!function_relocation::get_module_sections(mainPath.c_str(), moduleMain)) {
        spdlog::error("failed to get module sections for {}", mainPath);
        return;
    }

    const auto target = find_build_type_function(moduleMain);
    if (!target) {
        spdlog::error("failed to locate GetBuildType function by binary signature");
        return;
    }

    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
    auto replace_result = gum_interceptor_replace(
        interceptor,
        reinterpret_cast<void *>(target),
        reinterpret_cast<void *>(&forced_get_build_type),
        nullptr,
        reinterpret_cast<void **>(&original_get_build_type));
    if (replace_result != GUM_REPLACE_OK) {
        spdlog::error("failed to replace GetBuildType at {}: {}",
                      reinterpret_cast<void *>(target), static_cast<int>(replace_result));
        return;
    }

    patched = true;
    spdlog::info("patched GetBuildType at {} to force dev build type", reinterpret_cast<void *>(target));
#else
    (void) mainPath;
#endif
}

struct CoreVmPlugin final : IPlugin {
    PluginManifest man{};

    CoreVmPlugin() {
        man.id = "core.vm";
        man.version = "0.2.0";
        man.phases = PluginPhase::EarlyNative;
        man.support_reload = false;
        // High priority (low number): native VM face before feature plugins.
        man.priority = 10;
        man.options.kind = OptionRuleKind::AlwaysOn;
    }

    const PluginManifest &manifest() const override { return man; }

    bool can_load(const PluginContext &) const override { return true; }

    void load(PluginContext &) override {
        // Per-DLL function_relocation static state (capstone handle). Signature path
        // also inits/refcounts in ds_core_vm_run_signature_and_replace; load is a
        // belt-and-suspenders for EarlyNative when VM path already ran.
        (void) function_relocation::init_ctx();
        std::fprintf(stderr, "[plugin_core_vm] core.vm EarlyNative load\n");
    }

    void unload(PluginContext &) override {
        // Sticky for process lifetime.
    }
};

CoreVmPlugin g_core_vm;

bool run_signature_and_replace(const ds::core_vm::BootstrapArgs &args) {
    // function_relocation is a static lib — each DLL needs its own capstone/ctx.
    // Injector's init_ctx does not cover this module's copy.
    if (!function_relocation::init_ctx()) {
        showError("can't init signature");
        return false;
    }
    auto defer_ctx = create_defer(&function_relocation::deinit_ctx);

    auto lua51 = loadlib(lua51_name);
    if (!lua51) {
        showError("can't load lua51");
        return false;
    }
    auto defer1 = create_defer([&lua51]() {
        if (lua51)
            unloadlib(lua51);
    });

    spdlog::info("main module base address:{}",
                 (void *) gum_module_get_range(gum_process_get_main_module())->base_address);
    std::string mainPathOwned;
    const char *mainPathC = args.main_path;
    if (!mainPathC || !*mainPathC) {
        mainPathOwned = getExePath().string();
        mainPathC = mainPathOwned.c_str();
    }
    const std::string mainPath{mainPathC};

    if (luaModuleSignature.scan(mainPath.c_str()) == 0) {
        spdlog::error("can't find luamodule base address");
        return false;
    }
    ProcessMutex mtx("DontStarveInjectorSignature");
    std::lock_guard guard{mtx};
    const uintptr_t lua_base =
        args.lua_module_base != 0 ? args.lua_module_base : luaModuleSignature.target_address;
    auto res = SignatureUpdater::create_or_update(args.is_client, lua_base);
    if (!res) {
        showError(res.error());
        return false;
    }
    unloadlib(lua51);
    lua51 = nullptr;
    auto &val = res.value();
    ReplaceLuaModule(mainPath, val.signatures, val.exports);
    replace_game_branch_flag_to_dev(mainPath);
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
    host->register_plugin(&g_core_vm);
    std::fprintf(stderr, "[plugin_core_vm] module init registered core.vm\n");
    return true;
}

// Full signature + ReplaceLuaModule path (moved from Injector LegacySignatureAndReplaceInInjector).
// Hard failures call showError (exit). Soft miss (no luamodule base) returns false.
DS_PLUGIN_MODULE_EXPORT bool ds_core_vm_run_signature_and_replace(const ds::core_vm::BootstrapArgs *args) {
    if (!args) {
        spdlog::error("[plugin_core_vm] ds_core_vm_run_signature_and_replace: null args");
        return false;
    }
    std::fprintf(stderr, "[plugin_core_vm] running signature + ReplaceLuaModule\n");
    return run_signature_and_replace(*args);
}
