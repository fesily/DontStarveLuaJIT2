#pragma once
// PUC 5.1 dump attribution — the policy the generic C-function hook
// (game/CfunctionHook.hpp) runs on top of `string.dump`.
//
// The VM used to call a Lua closure from inside its own string_dump (a private-root policy
// slot). That made the dump path re-enter Lua and kept the owner name in VM error text. The
// attribution now lives here: a closure-implementation hook asks the blacklist manager who is
// calling (the manager's own policy function stays in the private root, where only our Lua
// code can reach it) and then calls the original implementation. The VM path is pure C.
#include "game/CfunctionHook.hpp"
#include "game/GameLuaContext.hpp"

namespace ds::core_vm::detail {

// True once the loaded VM image exposes the PUC 5.1 dump bridge (core.vm fills the slot).
// Without the bridge there is nothing to convert and nothing to attribute: a macro-off VM
// keeps the native LuaJIT dump and never records a caller.
void set_puc_dump_available(bool available);
bool puc_dump_available();

// Hooks `string.dump` for this state (one hook per state, before any mod runs). The closure
// object stays stock: same GCfunc, what="C", same upvalue count, same tostring and table keys.
bool install_dump_attribution(CfunctionHook &hooks, LuaApis &api, lua_State *L);

// The chook policy. Looks up the manager's policy in the private root and calls it with no
// arguments before the dump, so a hit is recorded even when the conversion itself fails. A
// policy that raises (ledger write failure) aborts the dump with its own error, exactly like
// the VM did when the callback lived inside string_dump.
int dump_attribution_policy(LuaApis &api, lua_State *L, lua_CFunction original, void *userdata);

} // namespace ds::core_vm::detail
