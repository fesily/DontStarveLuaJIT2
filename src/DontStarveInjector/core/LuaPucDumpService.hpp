#pragma once
// PUC Lua 5.1 bytecode dump service (DS: real Lua 5.1 string.dump for mods).
//
// The game VM (LuaJIT) keeps the exact source text of every successful text
// compile; this service turns one saved compile + one prototype identity back
// into genuine Lua 5.1 bytecode. It owns a private PUC 5.1 lua_State per call
// and never executes the source it compiles.
//
// The wire format is the POD ABI in 3rd/luajit/src/lua_ds_pucdump.h: no lua_State, no
// Proto and no C++ type crosses it. That header is included by the service
// translation unit and by the test host; it is deliberately NOT added to the
// Injector's include path, because Injector compiles against 3rd/lua51original
// headers and must never see a LuaJIT header. The entry point is published
// through the typed plugin service registry as "ds_lua_puc51_dump"; core.vm
// fills the VM's lj_ds_puc_dump data slot with it.

struct lua_DsPucDumpRequest;
struct lua_DsPucDumpResult;

namespace ds::puc51 {

// Returns 1 on success (result->owner/release transferred to the caller), 0 on
// failure with result->error filled in. Never throws.
int Dump(const lua_DsPucDumpRequest *request, lua_DsPucDumpResult *result) noexcept;

} // namespace ds::puc51
