#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include "disasm.h"

namespace function_relocation {

struct XrefWildcardPattern {
    std::string pattern;
    int pattern_offset = 0; // entry (body[0]) - window_start
    size_t insn_len = 0;
};

inline disasm::insn_type decode_xref(std::span<const uint8_t> body, size_t xref_off) {
    if (xref_off >= body.size()) return {};
    auto insn = disasm::get_insn(const_cast<uint8_t *>(body.data() + xref_off), body.size() - xref_off);
    if (!insn) return {};
    const auto &x86 = insn->detail->x86;
    if (x86.op_count != 2 || x86.operands[0].type != X86_OP_REG) return {};
    const auto &op = x86.operands[1];
    if ((insn->id == X86_INS_LEA || insn->id == X86_INS_MOV) && op.type == X86_OP_MEM && reg_is_ip(op.mem.base)) return insn;
    if ((insn->id == X86_INS_MOV || insn->id == X86_INS_MOVABS) && op.type == X86_OP_IMM) return insn;
    return {};
}

inline size_t xref_insn_len(std::span<const uint8_t> body, size_t xref_off) {
    auto insn = decode_xref(body, xref_off);
    return insn ? insn->size : 0;
}

inline std::string xref_hex_byte(uint8_t b) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s;
    s.push_back(kHex[b >> 4]);
    s.push_back(kHex[b & 0xf]);
    return s;
}

// Window around the string-xref insn, clamped to the body. Wildcard only the
// 4-byte RIP displacement or imm32. pattern_offset maps a gum match at
// window_start back to entry.
inline XrefWildcardPattern make_xref_wildcard_pattern(std::span<const uint8_t> body,
                                                      size_t xref_off, size_t pad = 16) {
    XrefWildcardPattern out;
    auto insn = decode_xref(body, xref_off);
    if (!insn) return out;
    const size_t insn_len = insn->size;
    const auto &x86 = insn->detail->x86;
    const bool immediate = x86.operands[1].type == X86_OP_IMM;
    const size_t field_offset = immediate ? x86.encoding.imm_offset : x86.encoding.disp_offset;
    const size_t field_size = immediate ? x86.encoding.imm_size : x86.encoding.disp_size;
    if (field_offset == 0 || field_size == 0 || field_offset + field_size > insn_len) return out;
    const size_t win_lo = xref_off > pad ? xref_off - pad : 0;
    const size_t win_hi = std::min(body.size(), xref_off + insn_len + pad);
    const size_t wild_lo = xref_off + field_offset;
    const size_t wild_hi = wild_lo + field_size;
    std::string pat;
    pat.reserve((win_hi - win_lo) * 3);
    for (size_t i = win_lo; i < win_hi; ++i) {
        if (!pat.empty()) {
            pat.push_back(' ');
        }
        if (i >= wild_lo && i < wild_hi) {
            pat += "??";
        } else {
            pat += xref_hex_byte(body[i]);
        }
    }
    out.pattern = std::move(pat);
    out.pattern_offset = -static_cast<int>(win_lo);
    out.insn_len = insn_len;
    return out;
}

} // namespace function_relocation
