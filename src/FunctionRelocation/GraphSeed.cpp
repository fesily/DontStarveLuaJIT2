#include "GraphSeed.hpp"
#include "CallTargetResolver.hpp"
#include "disasm.h"

namespace function_relocation {

    std::vector<uint64_t> collect_rel32_call_targets(uint64_t start, size_t size) {
        std::vector<uint64_t> out;
        if (start == 0 || size == 0) return out;
        disasm code{reinterpret_cast<uint8_t *>(start), size};
        for (const auto &insn: code) {
            const auto &x86 = insn.detail->x86;
            if ((insn.id == X86_INS_CALL || insn.id == X86_INS_JMP) &&
                x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM)
                out.push_back(static_cast<uint64_t>(x86.operands[0].imm));
        }
        return out;
    }

    std::vector<uint64_t> collect_rel32_call_targets(const ModuleSections &module, uint64_t start, size_t size) {
        auto targets = collect_rel32_call_targets(start, size);
        for (auto &target: targets) target = detail::resolve_call_target(module, target);
        return targets;
    }

    size_t reloc_free_prefix_len(const uint8_t *p, size_t n, size_t cap) {
        if (!p || n == 0) return 0;
        size_t length = 0;
        disasm code{const_cast<uint8_t *>(p), n};
        for (const auto &insn: code) {
            if (length + insn.size > cap) break;
            const auto &x86 = insn.detail->x86;
            bool reloc = insn.id == X86_INS_CALL || insn.id == X86_INS_JMP;
            for (uint8_t i = 0; i < x86.op_count; ++i) {
                const auto &op = x86.operands[i];
                reloc |= op.type == X86_OP_MEM && reg_is_ip(op.mem.base);
                // No module context here: conservatively end at register immediates.
                reloc |= (insn.id == X86_INS_MOV || insn.id == X86_INS_MOVABS) && op.type == X86_OP_IMM;
            }
            if (reloc) break;
            length += insn.size;
        }
        return length;
    }

}// namespace function_relocation
