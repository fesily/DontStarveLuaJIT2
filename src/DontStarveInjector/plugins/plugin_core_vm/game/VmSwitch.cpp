// game/VmSwitch.cpp — VM switch coordinator + Request/Apply/Reinitialize/CreateState markers
#include "GameLua.hpp"
#include "game/GameLuaInternal.hpp"
#include "game/GameLuaContextImpl.hpp"
#include "VmConfig.hpp"
#include "LuajitVariantNames.hpp"
#include "config/ResolvedConfig.hpp"
#include "config/ConfigSession.hpp"

#include "DontStarveSignature.hpp"
#include "GameSignature.hpp"
#include "util/inlinehook.hpp"
#include "util/platform.hpp"
#include "util/lua_io2.hpp"
#include "util/lua51_object.hpp"
#include "io/gameio.h"
#include "lua_debugger_helper.hpp"
#include <string_view>
#include <map>
#include <spdlog/spdlog.h>
#include <functional>
#include <list>
#include <cctype>
#include <optional>
#include <ranges>
#include <fmt/format.h>
#include <fmt/ranges.h>
#include <fstream>
#include <zlib.h>
#include <cassert>
using namespace std::literals;
using ds::core_vm::detail::PrepareForLuaStateCreate;
using ds::core_vm::detail::MarkLuaStateCreated;
using ds::core_vm::detail::MarkLuaStateClosed;
using ds::core_vm::detail::RequestVmType;
using ds::core_vm::detail::ReinitializeCurrentVm;
using ds::core_vm::detail::CreateLuaStateForCurrentVm;
using ds::core_vm::detail::UseGameIO;
using ds::core_vm::detail::load_game_fn_io_open;
using ds::core_vm::detail::replace_game_io_open;
using ds::core_vm::detail::CacheRuntimeSetup;
using ds::core_vm::detail::GetContextForType;
using ds::core_vm::detail::GetDefaultModuleName;
using ds::core_vm::detail::ApplyVmType;

#ifndef _WIN32
#include <dlfcn.h>
#else
#include <Windows.h>
#include <DbgHelp.h>
#pragma comment(lib, "dbghelp.lib")
#endif

#ifdef _WIN32
#define SHARED_LIBRARY_EXT ".dll"
#define SHARED_LIBRARY_PRE ""
#elif defined(__linux__)
#define SHARED_LIBRARY_EXT ".so"
#define SHARED_LIBRARY_PRE "lib"
#elif defined(__APPLE__)
#define SHARED_LIBRARY_EXT ".dylib"
#define SHARED_LIBRARY_PRE "lib"
#endif

using ds::core_vm::detail::DefaultLua51LibraryName;
using ds::core_vm::detail::DefaultLuajitLibraryName;
using ds::core_vm::detail::DefaultLuajitGenLibraryName;

namespace {
struct VmSwitchCoordinator {
    GameLuaType pendingType = GameLuaType::jit;
    std::optional<std::string> pendingModuleName;
    lua_State *liveState = nullptr;
    bool hasPendingSwitch = false;
    bool hasRuntimeSetup = false;
    std::string mainPath;
    Signatures signatures;
    ListExports_t exports;
};

VmSwitchCoordinator vmSwitchCoordinator;

GameLuaType GetCurrentVmType() {
    auto *currentCtx = GameLuaContextImpl::currentCtx;
    return currentCtx ? currentCtx->luaType : GameLuaType::jit;
}

std::optional<std::string> NormalizeModuleName(const char *moduleName) {
    if (moduleName == nullptr || moduleName[0] == '\0') {
        return std::nullopt;
    }
    if (!std::filesystem::exists(moduleName)) {
        spdlog::warn("Ignore Lua VM module override because file does not exist: {}", moduleName);
        return std::nullopt;
    }
    return std::string{moduleName};
}

void ApplyPendingVmType(std::string_view reason);

GameLuaType GetNextVmType() {
    return vmSwitchCoordinator.hasPendingSwitch ? vmSwitchCoordinator.pendingType : GetCurrentVmType();
}
} // namespace

namespace ds::core_vm::detail {

GameLuaContextImpl *GetContextForType(GameLuaType type) {
    switch (type) {
        case GameLuaType::_51:
            return ctx_lua51();
        case GameLuaType::jit:
            return ctx_jit();
        case GameLuaType::jit_gen:
            return ctx_jit_gen();
        case GameLuaType::game:
            return ctx_game();
        default:
            return ctx_jit();
    }
}

const char *GetDefaultModuleName(GameLuaType type) {
    // GameLuaType::game and ::unknown have no shared library.
    if (type == GameLuaType::game || type == GameLuaType::unknown) {
        return "";
    }
    // Look up the full platform library name from the centralized variant
    // table.  Falls back to the default JIT variant if the type is not found.
    switch (type) {
        case GameLuaType::_51:
            return DefaultLua51LibraryName();
        case GameLuaType::jit:
            return DefaultLuajitLibraryName();
        case GameLuaType::jit_gen:
            return DefaultLuajitGenLibraryName();
        default:
            return DefaultLuajitLibraryName();
    }
}

void ApplyVmType(GameLuaType type, const std::optional<std::string> &moduleName, std::string_view reason) {
    GameLuaContextImpl::currentCtx = GetContextForType(type);
    auto *targetCtx = GameLuaContextImpl::currentCtx;
    targetCtx->SetLibraryName(moduleName.value_or(GetDefaultModuleName(type)).c_str());
    spdlog::info("Applied Lua VM type: {} reason={} module={}",
                 GameLuaTypeToString(type),
                 reason,
                 targetCtx->GetLibraryName());
}

void CacheRuntimeSetup(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports) {
    vmSwitchCoordinator.hasRuntimeSetup = true;
    vmSwitchCoordinator.mainPath = mainPath;
    vmSwitchCoordinator.signatures = signatures;
    vmSwitchCoordinator.exports = exports;
}

void RequestVmType(GameLuaType type, const char *moduleName, std::string_view reason) {
    auto currentType = GetCurrentVmType();
    if (GameLuaContextImpl::currentCtx != nullptr && type == currentType) {
        if (vmSwitchCoordinator.hasPendingSwitch) {
            vmSwitchCoordinator.hasPendingSwitch = false;
            vmSwitchCoordinator.pendingModuleName.reset();
            spdlog::info("Cancel pending Lua VM switch because request matches current vm type: {} reason={}",
                         GameLuaTypeToString(type),
                         reason);
        } else {
            spdlog::info("Ignore Lua VM switch request because current vm type already is: {} reason={}",
                         GameLuaTypeToString(type),
                         reason);
        }
        return;
    }
    auto normalizedModuleName = NormalizeModuleName(moduleName);
    if (vmSwitchCoordinator.liveState != nullptr) {
        vmSwitchCoordinator.pendingType = type;
        vmSwitchCoordinator.pendingModuleName = std::move(normalizedModuleName);
        vmSwitchCoordinator.hasPendingSwitch = true;
        spdlog::info("Deferred Lua VM switch request: active={} pending={} reason={}",
                     GameLuaTypeToString(currentType),
                     GameLuaTypeToString(type),
                     reason);
        return;
    }
    ApplyVmType(type, normalizedModuleName, reason);
}

bool ReinitializeCurrentVm(std::string_view reason) {
    if (!vmSwitchCoordinator.hasRuntimeSetup) {
        spdlog::warn("Skip Lua VM runtime initialization because setup cache is not ready: {}", reason);
        return false;
    }
    auto *currentCtx = GameLuaContextImpl::currentCtx;
    if (currentCtx == nullptr) {
        spdlog::error("GameLuaContext is not initialized, cannot reinitialize Lua VM: {}", reason);
        return false;
    }
    if (!currentCtx->LoadLuaModule()) {
        return false;
    }
    currentCtx->LoadAllInterfaces();
    currentCtx->LoadMyLuaApi();
    if (!currentCtx->ReplaceApis(vmSwitchCoordinator.signatures, vmSwitchCoordinator.exports)) {
        spdlog::error("Failed to replace Lua APIs while reinitializing vm type {}: {}",
                      GameLuaTypeToString(GetCurrentVmType()),
                      reason);
        return false;
    }
    currentCtx->HotfixApis(vmSwitchCoordinator.mainPath);
    spdlog::info("Reinitialized Lua VM runtime: {} vm={}", reason, GameLuaTypeToString(GetCurrentVmType()));
    return true;
}

lua_State *CreateLuaStateForCurrentVm(lua_Alloc f, void *ud, std::string_view entryName) {
    PrepareForLuaStateCreate(entryName);
    auto &ctx = GetGameLuaContext();
    lua_event_notifyer(LUA_EVENT::new_state, nullptr);

    lua_State *L = nullptr;
    if (ctx.luaType == GameLuaType::jit || ctx.luaType == GameLuaType::jit_gen) {
        L = ctx.api._luaL_newstate();
    } else {
        L = ctx.api._lua_newstate(f, ud);
    }

    MarkLuaStateCreated(L, entryName);
    spdlog::info("{}:{} vm={}", entryName, (void *) L, GameLuaTypeToString(ctx.luaType));
    return L;
}

void PrepareForLuaStateCreate(std::string_view entryName) {
    if (vmSwitchCoordinator.liveState == nullptr) {
        ApplyPendingVmType(entryName);
    }
}

void MarkLuaStateCreated(lua_State *L, std::string_view entryName) {
    vmSwitchCoordinator.liveState = L;
    auto ctx = GameLuaContextImpl::currentCtx;
    if (ctx != nullptr) {
        ctx->luaState = L;
        spdlog::info("{} created lua state={} vm={}",
                     entryName,
                     (void *) L,
                     GameLuaTypeToString(ctx->luaType));
    }
}

void MarkLuaStateClosed(lua_State *L, std::string_view entryName) {
    auto ctx = GameLuaContextImpl::currentCtx;
    if (ctx != nullptr && ctx->luaState == L) {
        ctx->luaState = nullptr;
    }
    vmSwitchCoordinator.liveState = nullptr;
    spdlog::info("{} closed lua state={} vm={}",
                 entryName,
                 (void *) L,
                 ctx ? GameLuaTypeToString(ctx->luaType) : "unknown"sv);
}

} // namespace ds::core_vm::detail

namespace {
void ApplyPendingVmType(std::string_view reason) {
    if (!vmSwitchCoordinator.hasPendingSwitch) {
        return;
    }
    auto *previousCtx = GameLuaContextImpl::currentCtx;
    auto pendingType = vmSwitchCoordinator.pendingType;
    auto pendingModuleName = vmSwitchCoordinator.pendingModuleName;
    vmSwitchCoordinator.hasPendingSwitch = false;
    vmSwitchCoordinator.pendingModuleName.reset();
    if (previousCtx != nullptr && vmSwitchCoordinator.hasRuntimeSetup) {
        previousCtx->ResetApis(vmSwitchCoordinator.signatures, vmSwitchCoordinator.exports);
    }
    ds::core_vm::detail::ApplyVmType(pendingType, pendingModuleName, reason);
    ds::core_vm::detail::ReinitializeCurrentVm(reason);
}
} // namespace

static
void set_vm_type(GameLuaType type, const char *moduleName) {
    RequestVmType(type, moduleName, "set_vm_type");
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_set_vm_type(const char *type, const char *moduleName) {
    set_vm_type(GameLuaTypeFromString(type), moduleName);
}


DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_get_vm_type_name(int next) {
    return GameLuaTypeToString(next ? GetNextVmType() : GetCurrentVmType()).data();
}
