#include "CallTargetResolver.hpp"
#include "FunctionDiscovery.hpp"
#include "ModuleSections.hpp"
#include "disasm.h"

#include <cstring>

namespace function_relocation::detail {

    namespace {

        // 8 hops are allowed; the instruction reached after the last hop is still
        // inspected, so a body at exactly the hop limit resolves.
        constexpr size_t kMaxThunkHops = 8;

        enum class ThunkStep {
            Failed,    // unreadable or undecodable first instruction
            NotAThunk, // decodable, but not a jump this path follows: it is a body
            Jump,      // a followed jump whose destination is in `next`
            Unresolved // a recognised thunk whose destination cannot be read
        };

        // Decode one jump-thunk step at `current`.
        // `skip_padding` keeps the ScanCtx graph semantics (NOP / ENDBR before the
        // jump); `canonical_only` restricts the accepted encodings to the entry
        // thunks discovery recognises: `E9 rel32` and `FF 25 [rip+disp32]`.
        ThunkStep decode_thunk_step(const ModuleSections &module, uintptr_t current, cs_insn &insn,
                                    bool skip_padding, bool canonical_only, uintptr_t &next) {
            const auto *code = reinterpret_cast<const uint8_t *>(current);
            // Bound every decode to readable bytes, including thunks at a page
            // boundary.
            size_t size = 32;
            while (size != 0 && !gum_memory_is_readable(code, size)) --size;
            if (size == 0) return ThunkStep::Failed;
            uint64_t address = current;
            const auto hcs = get_ctx().hcs;
            next = 0;
            while (cs_disasm_iter(hcs, &code, &size, &address, &insn)) {
                if (skip_padding &&
                    (insn.id == X86_INS_ENDBR64 || insn.id == X86_INS_ENDBR32 || insn.id == X86_INS_NOP)) {
                    continue;
                }
                const auto &x86 = insn.detail->x86;
                if (insn.id != X86_INS_JMP || x86.op_count != 1) return ThunkStep::NotAThunk;
                const auto &op = x86.operands[0];
                if (op.type == X86_OP_IMM) {
                    if (canonical_only && !(insn.size == 5 && insn.bytes[0] == 0xe9)) {
                        return ThunkStep::NotAThunk;
                    }
                    next = static_cast<uintptr_t>(op.imm);
                    return ThunkStep::Jump;
                }
                if (op.type != X86_OP_MEM) return ThunkStep::NotAThunk;
                if (canonical_only &&
                    !(insn.size == 6 && insn.bytes[0] == 0xff && insn.bytes[1] == 0x25)) {
                    return ThunkStep::NotAThunk;
                }
                // Slot address only for the graph path; discovery reads the slot
                // because an entry thunk's body lives behind it.
                const uintptr_t slot = read_operand_rip_mem(insn, op);
                if (slot == 0) return ThunkStep::Unresolved;
#ifndef _WIN32
                if (!module.in_got_plt(slot)) return ThunkStep::Unresolved;
#endif
                if (!gum_memory_is_readable(reinterpret_cast<const void *>(slot), sizeof(next))) {
                    return ThunkStep::Unresolved;
                }
                std::memcpy(&next, reinterpret_cast<const void *>(slot), sizeof(next));
                if (next == 0) return ThunkStep::Unresolved;
                return ThunkStep::Jump;
            }
            return ThunkStep::Failed;
        }

    }// namespace

    uintptr_t resolve_pe_discovery_target(const ModuleSections &module, uintptr_t target,
                                          cs_insn &insn) {
        if (target == 0 || !module.in_module(target)) return 0;
        uintptr_t current = target;
        for (size_t hops = 0;; ++hops) {
            if (hops > kMaxThunkHops) return 0;// chain deeper than the hop limit
            uintptr_t next = 0;
            const auto step = decode_thunk_step(module, current, insn, /*skip_padding=*/false,
                                                /*canonical_only=*/true, next);
            switch (step) {
                case ThunkStep::NotAThunk:
                    return current;// this is the body
                case ThunkStep::Failed:
                case ThunkStep::Unresolved:
                    return 0;// not a resolvable entry
                case ThunkStep::Jump:
                    break;
            }
            if (next == 0 || next == current || !module.in_module(next)) return 0;
            current = next;
        }
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
            const auto step = decode_thunk_step(module, current, *insn, /*skip_padding=*/true,
                                                /*canonical_only=*/false, next);
            if (step != ThunkStep::Jump) return target;
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
