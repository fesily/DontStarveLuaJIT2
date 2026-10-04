#include "config/InjectorHostConfig.hpp"
#include "GameSignature.hpp"
#include "disasm.h"
#include <frida-gum.h>

function_relocation::MemorySignature luaModuleSignature{
#ifdef _WIN32
        "41 B8 EE D8 FF FF 41 3B D0 74 64 81 FA EF D8 FF FF 74 3B", -0x37
#elif defined(__linux__)
        "81 FE F1 D8 FF FF 7D 60 81 FE EF D8 FF FF 74 78 81 FE F0 D8 FF FF", -0x28
#elif defined(__APPLE__)
        "89 48 08 48 83 47 10 10 C3", -0xD, // luaA_pushobject
        //"3D EE D8 FF FF 74 18", -0x34     // index2adr
#else
#error "not support"
#endif
};

// Targets debug_getsize entry (via mid-body match + offset on Win/Linux; entry
// bytes on macOS x86_64). HotfixApis writes `ret` there so later GC-layout
// loads never run under LuaJIT.
function_relocation::MemorySignature luaRegisterDebugGetsizeSignature
        {
#ifdef _WIN32
                "4C 8B 5B 18 48 8B CB 49 8B",
                -0x27
#elif defined(__linux__)
                "48 8B 43 18 48 89 DF 48 8B 40 10",
                -0x1f
#elif defined(__APPLE__)
                "53 48 8B 47 18 8B 48 08 FF C9 83 F9 08",
                0
#else
#error "not support"
#endif
        };

// The engine's own lua_setexecutionerror-equivalent: a statically linked helper that
// publishes a 0x1000-byte message block through a `.data` flag slot (the slot holds the
// block pointer; NULL until armed). The engine's own error display reads those statics
// (win64 client: engine code at rva 0x102541 / 0x10254d, and luaD_pcall at rva 0x4f0a22
// reads the flag), so the swapped-in VM must write through them. HotfixApis decodes both
// slots from the matched window and hands them to the loaded VM. Shapes, measured RVAs
// and decode rules: docs/engine-execerror-slots.md.
function_relocation::MemorySignature luaSetExecutionErrorSignature
        {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
                "48 83 EC 28 48 83 3D ?? ?? ?? ?? 00 75 2A 48 8B D1 48 89 5C 24 20 "
                "48 8D 1D ?? ?? ?? ?? 48 8B CB 41 B8 00 10 00 00 FF 15 ?? ?? ?? ?? "
                "48 89 1D ?? ?? ?? ?? 48 8B 5C 24 20 48 83 C4 28 C3",
                0
#elif defined(__linux__) && defined(__x86_64__)
                "F3 0F 1E FA 48 83 3D ?? ?? ?? ?? 00 74 02 C3 90 48 83 EC 08 48 89 FE "
                "BA 00 10 00 00 48 8D 3D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? "
                "48 89 05 ?? ?? ?? ?? 48 83 C4 08 C3",
                0
#else
#error "luaSetExecutionErrorSignature: unsupported platform (win64/linux-x64 only; no 32-bit, macOS pattern not written)"
#endif
        };

// Execution-error storage decode for luaSetExecutionErrorSignature: the window starts at
// the engine's own setexecutionerror-equivalent; both slots are rip-relative (win64 /
// linux-x64). Anything unexpected — no 0x1000 size, no store back into the compared slot,
// equal slots — fails closed, so a wrong window can never hand bogus addresses to the VM.
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
            if (storage.buffer == 0 && insn.id == X86_INS_LEA && i == 1) {
                storage.buffer = mem_target(insn, op);
            }
        }
        if (storage.flag == 0 && insn.id == X86_INS_CMP && x86.op_count == 2 &&
            x86.operands[0].type == X86_OP_MEM && x86.operands[1].type == X86_OP_IMM &&
            x86.operands[1].imm == 0) {
            storage.flag = mem_target(insn, x86.operands[0]);
        }
        if (storage.flag != 0 && insn.id == X86_INS_MOV && x86.op_count == 2 &&
            x86.operands[0].type == X86_OP_MEM &&
            mem_target(insn, x86.operands[0]) == storage.flag) {
            store_seen = true;
        }
    }
    if (!size_seen || !store_seen || storage.flag == storage.buffer) {
        return ExecutionErrorStorage{};
    }
    return storage;
}

} // namespace ds::core_vm::detail
