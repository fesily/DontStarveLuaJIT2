#include "UniqueSignature.hpp"
#include "MemorySignature.hpp"
#include "InstructionPattern.hpp"
#include "disasm.h"

#include <array>

namespace function_relocation {
    namespace {

        std::string target_instruction_pattern(const ModuleSections &module, const cs_insn &insn,
                                               bool keep_image_relative) {
            const auto &x86 = insn.detail->x86;
            const bool absolute_address =
                    (insn.id == X86_INS_MOV || insn.id == X86_INS_MOVABS) &&
                    x86.op_count == 2 && x86.operands[1].type == X86_OP_IMM &&
                    module.in_module(static_cast<uintptr_t>(x86.operands[1].imm));
            auto pattern = instruction_pattern(insn, absolute_address);
            if (!keep_image_relative) return pattern;
            const auto restore = [&](uint8_t offset, uint8_t size) {
                constexpr char hex[] = "0123456789abcdef";
                if (offset == 0 || size == 0 || offset + size > insn.size) return;
                for (size_t i = offset; i < offset + size; ++i) {
                    pattern[i * 3] = hex[insn.bytes[i] >> 4];
                    pattern[i * 3 + 1] = hex[insn.bytes[i] & 15];
                }
            };
            for (uint8_t i = 0; i < x86.op_count; ++i) {
                const auto &op = x86.operands[i];
                if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP &&
                    module.in_module(insn.address + insn.size + op.mem.disp))
                    restore(x86.encoding.disp_offset, x86.encoding.disp_size);
            }
            bool relative_branch = false;
            for (uint8_t i = 0; i < insn.detail->groups_count; ++i)
                relative_branch |= insn.detail->groups[i] == CS_GRP_BRANCH_RELATIVE;
            if (relative_branch && x86.op_count == 1 && x86.operands[0].type == X86_OP_IMM &&
                module.in_module(static_cast<uintptr_t>(x86.operands[0].imm)))
                restore(x86.encoding.imm_offset, x86.encoding.imm_size);
            return pattern;
        }

        bool generate_from(const ModuleSections &module, std::span<const GumMemoryRange> ranges,
                           uintptr_t entry, size_t size, bool keep_image_relative,
                           SignatureInfo &signature) {
            SignatureInfo candidate{signature.offset, {}, 0};
            // Check only a few instruction-aligned lengths. Short identical
            // wrappers can use nearby code as context, still scanned across
            // the whole supplied Lua-base domain.
            constexpr std::array<size_t, 6> budgets{16, 32, 64, 128, 256, 512};
            size_t next_budget = 0;
            size_t decoded = 0;
            disasm code{reinterpret_cast<uint8_t *>(entry), size};
            for (const auto &insn: code) {
                if (!candidate.pattern.empty()) candidate.pattern.push_back(' ');
                candidate.pattern += target_instruction_pattern(module, insn, keep_image_relative);
                decoded += insn.size;
                if (next_budget < budgets.size() && decoded >= budgets[next_budget]) {
                    if (validate_unique_signature(ranges, candidate, entry)) {
                        signature = std::move(candidate);
                        return true;
                    }
                    while (next_budget < budgets.size() && decoded >= budgets[next_budget]) ++next_budget;
                }
            }
            if (!candidate.pattern.empty() && validate_unique_signature(ranges, candidate, entry)) {
                signature = std::move(candidate);
                return true;
            }
            return false;
        }

    }// namespace

    GumMemoryRange signature_search_range(const ModuleSections &module, uintptr_t lower_bound) {
        if (lower_bound < module.text.base_address || lower_bound - module.text.base_address >= module.text.size) return {};
        return {lower_bound, module.text.size - (lower_bound - module.text.base_address)};
    }

    bool validate_unique_signature(std::span<const GumMemoryRange> ranges, const SignatureInfo &signature,
                                   uintptr_t expected_entry) {
        if (ranges.empty() || signature.pattern.empty() || expected_entry == 0) return false;
        MemorySignature probe{signature.pattern.c_str(), 0, false};
        probe.log = false;
        uintptr_t hit = 0;
        for (const auto &range: ranges) {
            if (range.base_address == 0 || range.size == 0) continue;
            probe.scan(range.base_address, range.size);
            for (auto address: probe.targets) {
                if (hit != 0 && address != hit) return false;
                hit = address;
            }
        }
        if (hit == 0) return false;
        const auto offset = static_cast<int64_t>(signature.pattern_offset);
        if (offset >= 0) {
            return static_cast<uintptr_t>(offset) <= UINTPTR_MAX - hit &&
                   hit + static_cast<uintptr_t>(offset) == expected_entry;
        }
        const auto distance = static_cast<uintptr_t>(-offset);
        return hit >= distance && hit - distance == expected_entry;
    }

    bool make_unique_signature(const ModuleSections &module, std::span<const GumMemoryRange> ranges,
                               uintptr_t entry, SignatureInfo &signature) {
        if (entry < module.text.base_address || entry - module.text.base_address >= module.text.size) return false;
        if (validate_unique_signature(ranges, signature, entry)) return true;
        const size_t remaining = module.text.size - (entry - module.text.base_address);
        const auto *body = module.function_table.span_containing(entry);
        const size_t body_size = body ? (std::min)(remaining, static_cast<size_t>(body->end - entry)) : 0;
        // Prefer relocatable patterns contained in the function. Then preserve
        // image-relative fields; finally extend into adjacent code as context
        // for tiny functions with identical bodies. Never narrow the supplied
        // Lua-base search domain using the individual function's cached RVA.
        if (body_size != 0) {
            const size_t size = (std::min)(body_size, size_t{512});
            if (generate_from(module, ranges, entry, size, false, signature) ||
                generate_from(module, ranges, entry, size, true, signature)) return true;
        }
        return generate_from(module, ranges, entry, (std::min)(remaining, size_t{512}), true, signature);
    }

}// namespace function_relocation
