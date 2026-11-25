#pragma once
// Generic C-function hook: point a Lua closure's implementation pointer at our own function, so
// there is no hook layer at all -- no entry redirect, no trampoline, no dispatch polymorphism,
// no Lua-frame reflection.
//
// A closure is a GC object; lua_topointer() is that object, and a plain C closure stores its
// implementation pointer inside it. That field differs per VM build (LuaJIT GC64 vs the engine's
// PUC 5.1), so its offset is calibrated once per install instead of hardcoded (see
// calibrate_implementation_field): create a probe closure, find the word equal to its code
// address, and verify the location by writing through it and reading it back via
// lua_tocfunction().
//
// Each hook owns one dedicated thunk slot (template index), which knows its original
// implementation and policy: attribution costs nothing at call time. A thunk must never be
// shared, because nothing identifies which closure called it.
//
// Scope: plain C functions only (lua_tocfunction() exposes an implementation for them). Lua's
// builtin fast functions are dispatched by ffid and never read this field, so they are out of
// scope by construction; C API exports (lua_gc, lua_loadbuffer, ...) are not closures at all.
//
// The object stays otherwise stock: same GCfunc, what="C", same upvalue count, same tostring,
// same table keys, nothing in debug.getregistry(). Only the implementation word differs, which
// Lua cannot observe (a native reader can -- the price of removing the hook layer).
//
// The slot table is class-wide because the thunks are static functions; that is sound while only
// one VM has a live state (ApplyPendingVmType switches once the previous state is closed). Slots
// are released per state at lua_close, whose closures are gone; nothing is ever written back into
// a freed object.
#include "game/GameLuaContext.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace ds::core_vm::detail {

// Runs in place of the hooked implementation, with the caller's arguments already on the stack.
// It must call `original(L)` -- the unhooked implementation -- and return its result count like
// a lua_CFunction; calling the Lua object instead re-enters the thunk. C functions return the
// TOP `n` stack slots as results, so leave nothing above them.
using CfuncPolicy = int (*)(LuaApis &api, lua_State *L, lua_CFunction original, void *userdata);

class CfunctionHook {
public:
    using Policy = CfuncPolicy;

    // Number of simultaneously hooked closures. The table is bounded because every hook needs its
    // own thunk (nothing identifies the caller), so size it for the real load: two per state
    // (require/kleiloadlua) with room to spare; slots are recycled at lua_close.
    static constexpr int kSlots = 32;

    // Points the implementation of the C closure at `index` at a dedicated thunk. A closure that
    // already has a thunk of ours cannot be hooked twice; the same implementation reached
    // through another closure gets its own slot. Returns false for a Lua function, a builtin
    // fast function, an unsupported closure layout, or an exhausted slot table.
    bool hook(LuaApis &api, lua_State *L, int index, Policy policy, void *userdata);

    // Same, for the global `name`; leaves the stack unchanged.
    bool hook_global(LuaApis &api, lua_State *L, const char *name, Policy policy, void *userdata);

    // A closed state's closures are gone: free their slots without touching the memory.
    void drop_state(lua_State *L);

    // Frees every slot (VM teardown). Never writes back into a closure, whose state may be gone.
    void clear();

    size_t hook_count() const;

private:
    struct Slot {
        lua_State *L{nullptr};
        const void *object{nullptr};
        LuaApis *api{nullptr};
        lua_CFunction original{nullptr};
        Policy policy{nullptr};
        void *userdata{nullptr};
    };

    // Where a plain C closure keeps its implementation pointer, or 0 when the layout was not
    // recognized.
    static size_t calibrate_implementation_field(LuaApis &api, lua_State *L);
    static void write_implementation(void *object, size_t offset, lua_CFunction fn);

    static std::array<Slot, kSlots> slots_;

public:
    // One body per slot; the table of their addresses lives in the .cpp. Public because the
    // address of a private member function cannot be taken outside the class.
    template <int I>
    static int thunk(lua_State *L);
};

} // namespace ds::core_vm::detail
