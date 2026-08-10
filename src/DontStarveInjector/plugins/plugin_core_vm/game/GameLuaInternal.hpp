// game/GameLuaInternal.hpp — internal multi-TU helpers for plugin_core_vm.
// Not a peer-facing surface; peers must keep using GameLua.hpp / GameLuaContext.hpp.
#pragma once

#include "game/GameLuaContext.hpp"
#include "DontStarveSignature.hpp"

#include <optional>
#include <string>
#include <string_view>

struct GameLuaContextImpl; // defined in game/GameLuaContextImpl.hpp

namespace ds::core_vm::detail {

// Context selection / naming
GameLuaContextImpl *GetContextForType(GameLuaType type);
const char *GetDefaultModuleName(GameLuaType type);

// VM switch / lifecycle (definitions remain in GameLua.cpp for Task 3)
void RequestVmType(GameLuaType type, const char *moduleName, std::string_view reason);
bool ReinitializeCurrentVm(std::string_view reason);
void ApplyVmType(GameLuaType type, const std::optional<std::string> &moduleName, std::string_view reason);
void CacheRuntimeSetup(const std::string &mainPath, const Signatures &signatures, const ListExports_t &exports);

// Lua state lifecycle around CreateLuaStateForCurrentVm
lua_State *CreateLuaStateForCurrentVm(lua_Alloc f, void *ud, std::string_view entryName);
void PrepareForLuaStateCreate(std::string_view entryName);
void MarkLuaStateCreated(lua_State *L, std::string_view entryName);
void MarkLuaStateClosed(lua_State *L, std::string_view entryName);

// GAME_IO helpers (used from context openlibs / ReplaceApis paths)
bool UseGameIO();
void load_game_fn_io_open(const Signatures &signatures);
void replace_game_io_open(GameLuaContext &ctx, lua_State *L);

// Task 4 will define these next to each context static instance.
// Declared now so GetContextForType can switch to function accessors later.
GameLuaContextImpl *ctx_lua51();
GameLuaContextImpl *ctx_jit();
GameLuaContextImpl *ctx_jit_gen();
GameLuaContextImpl *ctx_game();

// Platform full library filenames for VM variants (defined in GameLuaContext.cpp)
const char *DefaultLua51LibraryName();
const char *DefaultLuajitLibraryName();
const char *DefaultLuajitGenLibraryName();

// Used by ReplaceLuaModule while it still lives in GameLua.cpp (Task 5 moves it)
void NoteGameLuaExport(const std::string &name, GumAddress addr);
void NoteGameLuaExportsForDebugSymbols();

} // namespace ds::core_vm::detail
