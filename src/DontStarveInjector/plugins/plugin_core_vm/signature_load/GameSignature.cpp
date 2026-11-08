#include "config/InjectorHostConfig.hpp"
#include "GameSignature.hpp"
#include "disasm.h"
#include "util/LinuxGameSignatures.hpp"
#include <frida-gum.h>

#ifdef __linux__
function_relocation::MemorySignature luaModuleSignature{ds::linux_signatures::lua_module, 0};
#else
function_relocation::MemorySignature luaModuleSignature{
#ifdef _WIN32
        "41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B", -0x37
#elif defined(__APPLE__)
        "89 48 08 48 83 47 10 10 C3", -0xD, // luaA_pushobject
        //"3D EE D8 FF FF 74 18", -0x34     // index2adr
#else
#error "not support"
#endif
};
#endif

// macOS symbol luaopen_getsize establishes the registration contract. The
// GCC 9 Linux version loads the closure through rbp; its FDE supplies the entry.
#ifdef __linux__
function_relocation::MemorySignature luaRegisterDebugGetsizeSignature{ds::linux_signatures::register_debug_getsize, 0};
#else
function_relocation::MemorySignature luaRegisterDebugGetsizeSignature{
#ifdef _WIN32
        "4C 8B 5B 18 48 8B CB 49 8B", -0x27
#elif defined(__APPLE__)
        "53 48 8B 47 18 8B 48 08 FF C9 83 F9 08", 0
#else
#error "not support"
#endif
};
#endif

// The engine's own lua_setexecutionerror-equivalent: a statically linked helper that
// publishes a 0x1000-byte message block through a `.data` flag slot (the slot holds the
// block pointer; NULL until armed). The engine's own error display reads those statics
// (the `lua_getexecutionerror` getter loads the flag, and the protected-call wrapper
// overrides its status from the same flag), so the swapped-in VM must write through them.
// HotfixApis decodes both slots from the matched window and hands them to the loaded VM.
// Shapes, measured RVAs and decode rules: docs/engine-execerror-slots.md.
//
// The body was rewritten (win64 build 26474873, same change the Linux engine got in
// 759671): `strncpy` became an inlined strlen + bounded copy through the CRT's checked
// memcpy, with an empty-string fallback for a NULL message, so the copy length is now the
// `cmp reg, 0x1000` bound instead of a `mov r8d, 0x1000` argument and the prologue no
// longer starts with `mov rdx, rcx`.
function_relocation::MemorySignature luaSetExecutionErrorSignature
        {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
                "48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 76 48 85 C9 48 8D 15 ?? ?? ?? ?? "
                "48 89 5C 24 30 48 8D 1D ?? ?? ?? ?? 48 0F 45 D1 48 3B D3 74 4B "
                "48 83 C9 FF 48 89 7C 24 20 33 C0 48 8B FA F2 AE 48 F7 D1 48 FF C9 48 8B F9 "
                "48 81 F9 00 10 00 00 72 15 BF FF 0F 00 00 0F B6 04 17 24 C0 3C 80 75 06 "
                "48 83 EF 01 75 F0 4C 8B C7 48 8B CB E8 ?? ?? ?? ?? C6 04 1F 00 "
                "48 8B 7C 24 20 48 89 1D ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 28 C3",
                0
#elif defined(__linux__) && defined(__x86_64__)
        ds::linux_signatures::execution_error,
        0
#else
#error "luaSetExecutionErrorSignature: unsupported platform (win64/linux-x64 only; no 32-bit, macOS pattern not written)"
#endif
        };

// Execution-error storage decode for luaSetExecutionErrorSignature: the window starts at
// the engine's own setexecutionerror-equivalent; both slots are rip-relative (win64 /
// linux-x64). The block is the `lea` destination whose register is published into the
// compared flag slot — not simply the first `lea` of the window, because the rewritten
// bodies `lea` a read-only empty-string fallback (for a NULL message) before the block;
// taking that one would point the VM's 0x1000-byte copy into `.rdata`. Anything
// unexpected — no 0x1000 bound, no store back into the compared slot, a stored value that
// does not trace back to a `lea`, equal slots — fails closed, so a wrong window can never
// hand bogus addresses to the VM.
// Consumed by GameLuaContextImpl::HotfixApis (docs/engine-execerror-slots.md).
namespace ds::core_vm::detail {

ExecutionErrorStorage decode_execution_error_storage(uintptr_t helper) {
    ExecutionErrorStorage storage;
    if (helper == 0) {
        return storage;
    }
    const auto mem_target = [](const cs_insn &insn, const auto &op) -> uintptr_t {
        if (op.type != X86_OP_MEM || !function_relocation::reg_is_ip(op.mem.base)) {
            return 0;
        }
        return (uintptr_t) ((int64_t) (insn.address + insn.size) + (int64_t) op.mem.disp);
    };
    // Register -> rip-relative `lea` target seen so far (plus plain register moves, which
    // only forward an already known target). Small: the helper body is a handful of moves.
    struct LeaSource {
        unsigned reg = 0;
        uintptr_t target = 0;
    };
    constexpr size_t max_lea_sources = 8;
    LeaSource lea_sources[max_lea_sources];
    size_t lea_count = 0;
    const auto lea_forget = [&](unsigned reg) {
        for (size_t i = 0; i < lea_count; ++i) {
            if (lea_sources[i].reg == reg) {
                lea_sources[i] = lea_sources[--lea_count];
                return;
            }
        }
    };
    const auto lea_lookup = [&](unsigned reg) -> uintptr_t {
        for (size_t i = 0; i < lea_count; ++i) {
            if (lea_sources[i].reg == reg) {
                return lea_sources[i].target;
            }
        }
        return 0;
    };
    const auto lea_remember = [&](unsigned reg, uintptr_t target) {
        lea_forget(reg);
        if (target == 0) {
            return;
        }
        if (lea_count < max_lea_sources) {
            lea_sources[lea_count++] = LeaSource{reg, target};
        }
    };
    constexpr size_t window = 0xC0;
    function_relocation::disasm ds{std::span{(uint8_t *) helper, window}};
    bool size_seen = false;
    bool store_seen = false;
    for (auto &insn: ds) {
        if (insn.id == 0) {
            continue;
        }
        const auto &x86 = insn.detail->x86;
        for (int i = 0; i < x86.op_count; ++i) {
            const auto &op = x86.operands[i];
            if (op.type == X86_OP_IMM && op.imm == 0x1000) {
                size_seen = true;
            }
        }
        // Track where a register's value came from, so the flag store can be resolved.
        if (insn.id == X86_INS_LEA && x86.op_count == 2 && x86.operands[0].type == X86_OP_REG &&
            x86.operands[1].type == X86_OP_MEM) {
            lea_remember(x86.operands[0].reg, mem_target(insn, x86.operands[1]));
        } else if (insn.id == X86_INS_MOV && x86.op_count == 2 &&
                   x86.operands[0].type == X86_OP_REG) {
            lea_remember(x86.operands[0].reg,
                         x86.operands[1].type == X86_OP_REG ? lea_lookup(x86.operands[1].reg) : 0);
        }
        if (storage.flag == 0 && insn.id == X86_INS_CMP && x86.op_count == 2 &&
            x86.operands[0].type == X86_OP_MEM && x86.operands[1].type == X86_OP_IMM &&
            x86.operands[1].imm == 0) {
            storage.flag = mem_target(insn, x86.operands[0]);
        }
        if (storage.flag != 0 && insn.id == X86_INS_MOV && x86.op_count == 2 &&
            x86.operands[0].type == X86_OP_MEM &&
            x86.operands[1].type == X86_OP_REG &&
            mem_target(insn, x86.operands[0]) == storage.flag) {
            const uintptr_t block = lea_lookup(x86.operands[1].reg);
            if (block != 0) {
                storage.buffer = block;
                store_seen = true;
            }
        }
    }
    if (!size_seen || !store_seen || storage.flag == storage.buffer) {
        return ExecutionErrorStorage{};
    }
    return storage;
}

} // namespace ds::core_vm::detail
