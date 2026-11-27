#include "CallTargetResolver.hpp"
#include "FunctionDiscovery.hpp"
#include "ModuleSections.hpp"
#include "disasm.h"

#include <cstring>

namespace function_relocation::detail {

    namespace {

        // Decode one jump-thunk step at `current`: false on an unreadable or
        // undecodable instruction, `next == 0` when the instruction is not a
        // recognised jump thunk.
        // `skip_padding` keeps the ScanCtx graph semantics (NOP / ENDBR before the
        // jump); `canonical_only` restricts the accepted encodings to the entry
        // thunks discovery recognises: `E9 rel32` and `FF 25 [rip+disp32]`.
        bool decode_thunk_step(const ModuleSections &module, uintptr_t current, cs_insn &insn,
                               bool skip_padding, bool canonical_only, uintptr_t &next) {
            const auto *code = reinterpret_cast<const uint8_t *>(current);
            // Bound every decode to readable bytes, including thunks at a page
            // boundary.
            size_t size = 32;
            while (size != 0 && !gum_memory_is_readable(code, size)) --size;
            if (size == 0) return false;
            uint64_t address = current;
            const auto hcs = get_ctx().hcs;
            next = 0;
            while (cs_disasm_iter(hcs, &code, &size, &address, &insn)) {
                if (skip_padding &&
                    (insn.id == X86_INS_ENDBR64 || insn.id == X86_INS_ENDBR32 || insn.id == X86_INS_NOP)) {
                    continue;
                }
                const auto &x86 = insn.detail->x86;
                if (insn.id != X86_INS_JMP || x86.op_count != 1) return true;
                const auto &op = x86.operands[0];
                if (op.type == X86_OP_IMM) {
                    if (canonical_only && !(insn.size == 5 && insn.bytes[0] == 0xe9)) return true;
                    next = static_cast<uintptr_t>(op.imm);
                    return true;
                }
                if (op.type != X86_OP_MEM) return true;
                if (canonical_only &&
                    !(insn.size == 6 && insn.bytes[0] == 0xff && insn.bytes[1] == 0x25)) {
                    return true;
                }
                // Slot address only for the graph path; discovery reads the slot
                // because an entry thunk's body lives behind it.
                const uintptr_t slot = read_operand_rip_mem(insn, op);
                if (slot == 0) return true;
#ifndef _WIN32
                if (!module.in_got_plt(slot)) return true;
#endif
                if (!gum_memory_is_readable(reinterpret_cast<const void *>(slot), sizeof(next))) {
                    return true;
                }
                std::memcpy(&next, reinterpret_cast<const void *>(slot), sizeof(next));
                return true;
            }
            return false;
        }

    }// namespace

    uintptr_t resolve_pe_discovery_target(const ModuleSections &module, uintptr_t target,
                                          cs_insn &insn) {
        if (target == 0 || !module.in_module(target)) return 0;
        constexpr size_t hop_limit = 8;
        uintptr_t current = target;
        for (size_t hop = 0; hop < hop_limit; ++hop) {
            uintptr_t next = 0;
            if (!decode_thunk_step(module, current, insn, /*skip_padding=*/false,
                                   /*canonical_only=*/true, next)) {
                return 0;
            }
            if (next == 0) return current;// not a thunk: this is the body
            if (next == current || !module.in_module(next)) return 0;
            current = next;
        }
        return 0;// chain too long (or cyclic): no real body
    }

    uintptr_t resolve_call_target(const ModuleSections &module, uintptr_t target) {
        if (target == 0) return target;
#ifdef _WIN32
        // Preserve ScanCtx's PE thunk handling for targets inside the module.
        if (!module.in_module(target)) return target;
        constexpr size_t hop_limit = 1;
#else
        // File semantics first: a PLT stub carries the imported symbol NAME in the
        // module's static import table, and the reference module's own definition is
        // the authority for call-graph seeding. Reading the runtime GOT instead lets
        // any other library loaded earlier in the process interpose the slot
        // (measured in-engine: plugin_core_vm.so hijacks liblua51.so's
        // luaL_loadbuffer), which silently destroys the training-library call graph.
        if (module.in_plt(target)) {
            const auto *name = module.import_name_for_plt_target(target);
            if (name != nullptr) {
                // FILE symbol table first: it exists before function discovery.
                if (const auto own = module.own_definition_address(*name); own != 0) {
                    return own;
                }
                // A matching name in the function table cannot prove that this
                // module defines the dynamic import; genuine external imports must
                // fall back to their runtime GOT.
            }
        }
        if (!module.in_plt(target)) return target;
        constexpr size_t hop_limit = 8;
#endif
        uintptr_t current = target;
        const auto hcs = get_ctx().hcs;
        auto insn = disasm::malloc_insn(hcs);
        for (size_t hop = 0; hop < hop_limit; ++hop) {
            uintptr_t next = 0;
            if (!decode_thunk_step(module, current, *insn, /*skip_padding=*/true,
                                   /*canonical_only=*/false, next)) {
                return target;
            }
            // Lazy GOT entries may point back into the PLT; do not report an
            // intermediate stub as the callee when resolution cannot finish.
            if (next == 0 || next == current) return target;
#ifndef _WIN32
            if (module.in_plt(next)) {
                current = next;
                continue;
            }
#endif
            return next;
        }
        return target;
    }

}// namespace function_relocation::detail

namespace function_relocation {

    uintptr_t resolve_pe_discovery_target(const ModuleSections &module, uintptr_t target) {
#if defined(_WIN32)
        if (target == 0 || !module.in_module(target)) return 0;
        auto insn = disasm::malloc_insn(get_ctx().hcs);
        if (!insn) return 0;
        return detail::resolve_pe_discovery_target(module, target, *insn);
#else
        (void) module;
        (void) target;
        return 0;// PE entry thunks are a Windows concept
#endif
    }

}// namespace function_relocation
