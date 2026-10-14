#include "CallTargetResolver.hpp"
#include "ModuleSections.hpp"
#include "disasm.h"

#include <cstring>

namespace function_relocation::detail {

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
                // FILE symbol table first: it exists before Nucleus function tables.
                if (const auto own = module.own_definition_address(*name); own != 0) {
                    return own;
                }
                // Nucleus names include LOCAL symbols. A matching name there
                // cannot prove that this module defines the dynamic import;
                // genuine external imports must fall back to their runtime GOT.
            }
        }
        if (!module.in_plt(target)) return target;
        constexpr size_t hop_limit = 8;
#endif
        uintptr_t current = target;
        for (size_t hop = 0; hop < hop_limit; ++hop) {
            // Bound every decode to readable bytes, including thunks at a page
            // boundary.
            const auto *code = reinterpret_cast<const uint8_t *>(current);
            size_t size = 32;
            while (size != 0 && !gum_memory_is_readable(code, size)) --size;
            if (size == 0) return target;
            uint64_t address = current;
            const auto hcs = get_ctx().hcs;
            auto insn = disasm::malloc_insn(hcs);
            uintptr_t next = 0;
            while (cs_disasm_iter(hcs, &code, &size, &address, insn.get())) {
                if (insn->id == X86_INS_ENDBR64 || insn->id == X86_INS_ENDBR32 || insn->id == X86_INS_NOP) continue;
                const auto &x86 = insn->detail->x86;
                if (insn->id != X86_INS_JMP || x86.op_count != 1) break;
                const auto &op = x86.operands[0];
                if (op.type == X86_OP_IMM) {
                    next = static_cast<uintptr_t>(op.imm);
                } else if (op.type == X86_OP_MEM) {
                    const uintptr_t slot = read_operand_rip_mem(*insn, op);
                    if (slot == 0) break;
#ifndef _WIN32
                    if (!module.in_got_plt(slot)) break;
#endif
                    if (!gum_memory_is_readable(reinterpret_cast<const void *>(slot), sizeof(next))) break;
                    std::memcpy(&next, reinterpret_cast<const void *>(slot), sizeof(next));
                }
                break;
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
