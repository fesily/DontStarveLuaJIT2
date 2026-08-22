// game/ReplaceLuaModule.cpp — ReplaceLuaModule entry for VM startup
#include "GameLua.hpp"
#include "game/GameLuaInternal.hpp"
#include "VmConfig.hpp"
#include "config/ResolvedConfig.hpp"
#include "config/ConfigSession.hpp"
#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include <spdlog/spdlog.h>

using ds::core_vm::detail::CacheRuntimeSetup;
using ds::core_vm::detail::RequestVmType;
using ds::core_vm::detail::ReinitializeCurrentVm;

void ReplaceLuaModule(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    auto ictx = InjectorCtx::instance();

    // init game lua
    for (auto &[name, address]: exports) {
        auto offset = signatures.funcs.at(name).offset;
        auto target = (uint8_t *) GSIZE_TO_POINTER(luaModuleSignature.target_address + GPOINTER_TO_INT(offset));
        spdlog::info("Game export {}: {}", name, (void *) target);
        ds::core_vm::detail::NoteGameLuaExport(name, (GumAddress) target);
    }
    ds::core_vm::detail::NoteGameLuaExportsForDebugSymbols();
    CacheRuntimeSetup(mainPath, signatures, exports);
    auto luaType = GameLuaType::jit;
    (void) ds::config::ensure_resolved();
    if (auto *rc = ds::config::current()) {
        luaType = ds::core_vm::get_lua_vm_type(*rc);
    }

    RequestVmType(luaType, nullptr, "Default VM type setup");
    ReinitializeCurrentVm("ReplaceLuaModule startup");
}
