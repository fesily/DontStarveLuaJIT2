// game/CfunctionHook.cpp — implementation-pointer hooks (no hook layer).
//
// Each hooked closure gets a dedicated thunk slot that knows its original implementation and
// policy, so a call costs one extra call plus a slot load: no entry redirect, no trampoline, no
// reflection, no shared dispatcher.
//
// The implementation pointer lives inside the closure object (lua_topointer()). Its offset is a
// property of the VM build, so it is calibrated per install: build a probe closure, locate the
// word holding its code address, then verify by writing a different function through that word
// and reading it back with lua_tocfunction(). Wrong guesses are rejected before any real closure
// is touched.
#include "game/CfunctionHook.hpp"

#include <spdlog/spdlog.h>

#include <cstring>
#include <utility>

namespace ds::core_vm::detail {

std::array<CfunctionHook::Slot, CfunctionHook::kSlots> CfunctionHook::slots_{};

namespace {

template <int... I>
constexpr std::array<lua_CFunction, sizeof...(I)> make_thunks(std::integer_sequence<int, I...>) {
    return {{&CfunctionHook::thunk<I>...}};
}

constexpr std::array<lua_CFunction, CfunctionHook::kSlots> kThunks =
        make_thunks(std::make_integer_sequence<int, CfunctionHook::kSlots>{});

// Calibration probe bodies; they are never called.
static int probe_marker(lua_State *) { return 0; }
static int probe_alternate(lua_State *) { return 0; }

uintptr_t read_word(const void *base, size_t offset) {
    uintptr_t word = 0;
    std::memcpy(&word, static_cast<const char *>(base) + offset, sizeof(word));
    return word;
}

} // namespace

template <int I>
int CfunctionHook::thunk(lua_State *L) {
    const Slot &slot = slots_[I];
    if (slot.policy == nullptr || slot.api == nullptr || slot.original == nullptr) {
        return 0;
    }
    return slot.policy(*slot.api, L, slot.original, slot.userdata);
}

size_t CfunctionHook::calibrate_implementation_field(LuaApis &api, lua_State *L) {
    if (api._lua_pushcclosure == nullptr || api._lua_topointer == nullptr ||
        api._lua_tocfunction == nullptr) {
        return 0;
    }
    api._lua_pushcclosure(L, probe_marker, 0);
    const void *object = api._lua_topointer(L, -1);
    if (object == nullptr || api._lua_tocfunction(L, -1) != &probe_marker) {
        api._lua_pop(L, 1);
        return 0;
    }
    // The field is a plain pointer in the object's header area; scan the first words for the
    // code address we just installed.
    size_t offset = 0;
    for (size_t word = 0; word < 8 && offset == 0; word++) {
        const size_t candidate = word * sizeof(uintptr_t);
        if (read_word(object, candidate) == reinterpret_cast<uintptr_t>(&probe_marker)) {
            offset = candidate;
        }
    }
    if (offset != 0) {
        // Confirm the location: writing through it must be visible to lua_tocfunction().
        auto *field = reinterpret_cast<lua_CFunction *>(static_cast<char *>(const_cast<void *>(object)) +
                                                        offset);
        *field = probe_alternate;
        const bool visible = api._lua_tocfunction(L, -1) == &probe_alternate;
        *field = probe_marker;
        if (!visible) {
            offset = 0;
        }
    }
    api._lua_pop(L, 1);
    return offset;
}

void CfunctionHook::write_implementation(void *object, size_t offset, lua_CFunction fn) {
    auto *field = reinterpret_cast<lua_CFunction *>(static_cast<char *>(object) + offset);
    *field = fn;
}

bool CfunctionHook::hook(LuaApis &api, lua_State *L, int index, Policy policy, void *userdata) {
    if (policy == nullptr || L == nullptr) {
        return false;
    }
    lua_CFunction original = api._lua_tocfunction(L, index);
    if (original == nullptr) {
        // Lua function, builtin fast function (dispatched by ffid), or unknown closure kind.
        return false;
    }
    const void *object = api._lua_topointer != nullptr ? api._lua_topointer(L, index) : nullptr;
    if (object == nullptr) {
        return false;
    }
    const size_t offset = calibrate_implementation_field(api, L);
    if (offset == 0) {
        spdlog::error("[luajit] cannot locate the C closure implementation pointer of this VM");
        return false;
    }
    for (auto &slot: slots_) {
        if (slot.object != object) {
            continue;
        }
        // A slot whose closure no longer points at its thunk is stale: closures are freed with
        // their state and the next state's closure can land on the same address (measured), so
        // the object itself, not a remembered lua_State*, decides whether the hook is still live.
        if (read_word(object, offset) == reinterpret_cast<uintptr_t>(kThunks[(size_t) (&slot - slots_.data())])) {
            spdlog::warn("[luajit] C function at {} already has a hook", object);
            return false;
        }
        slot = Slot{};
    }
    for (int i = 0; i < kSlots; i++) {
        if (slots_[(size_t) i].object != nullptr) {
            continue;
        }
        Slot &slot = slots_[(size_t) i];
        slot = Slot{L, object, &api, original, policy, userdata};
        write_implementation(const_cast<void *>(object), offset, kThunks[(size_t) i]);
        return true;
    }
    spdlog::error("[luajit] C function hook table exhausted ({} hooks)", kSlots);
    return false;
}

bool CfunctionHook::hook_global(LuaApis &api, lua_State *L, const char *name, Policy policy,
                                void *userdata) {
    api._lua_getglobal(L, name);
    const bool hooked = hook(api, L, -1, policy, userdata);
    api._lua_pop(L, 1);
    if (!hooked) {
        spdlog::warn("[luajit] cannot hook {}", name);
    }
    return hooked;
}

void CfunctionHook::drop_state(lua_State *L) {
    size_t dropped = 0;
    for (auto &slot: slots_) {
        if (slot.L == L) {
            // The state's closures are gone with it: free the slot, never write the field back.
            slot = Slot{};
            dropped++;
        }
    }
    if (dropped != 0) {
        spdlog::info("[luajit] dropped {} cfunction hook slot(s) of state {}", dropped, (void *) L);
    }
}

void CfunctionHook::clear() {
    size_t cleared = 0;
    for (auto &slot: slots_) {
        if (slot.object != nullptr) {
            slot = Slot{};
            cleared++;
        }
    }
    if (cleared != 0) {
        spdlog::info("[luajit] cleared {} cfunction hook slot(s)", cleared);
    }
}

size_t CfunctionHook::hook_count() const {
    size_t count = 0;
    for (const auto &slot: slots_) {
        if (slot.object != nullptr) {
            count++;
        }
    }
    return count;
}

} // namespace ds::core_vm::detail
