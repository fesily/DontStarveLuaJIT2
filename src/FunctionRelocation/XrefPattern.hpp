#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace function_relocation {

struct XrefWildcardPattern {
    std::string pattern;
    int pattern_offset = 0; // entry (body[0]) - window_start
    size_t insn_len = 0;
};

// Same classification unique_const's target xref scanner uses.
inline size_t xref_insn_len(std::span<const uint8_t> body, size_t xref_off) {
    if (xref_off >= body.size()) {
        return 0;
    }
    const uint8_t b0 = body[xref_off];
    if (xref_off + 7 <= body.size() && b0 >= 0x40 && b0 <= 0x4f &&
        (body[xref_off + 1] == 0x8d || body[xref_off + 1] == 0x8b) &&
        (body[xref_off + 2] & 0xC7) == 0x05) {
        return 7;
    }
    if (xref_off + 5 <= body.size() && b0 >= 0xB8 && b0 <= 0xBF) {
        return 5;
    }
    return 0;
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
    const size_t insn_len = xref_insn_len(body, xref_off);
    if (insn_len == 0) {
        return out;
    }
    const size_t win_lo = xref_off > pad ? xref_off - pad : 0;
    const size_t win_hi = std::min(body.size(), xref_off + insn_len + pad);
    const size_t wild_lo = xref_off + (insn_len - 4);
    const size_t wild_hi = xref_off + insn_len;
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
