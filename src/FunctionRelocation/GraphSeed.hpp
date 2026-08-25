#pragma once

#include <cstdint>
#include <cstring>
#include <unordered_set>
#include <vector>

namespace function_relocation {

// Naive E8/E9 rel32 walk (same as body_calls_entry). Returns raw call/jmp
// targets — not FunctionTable starts. Interior exports that Nucleus merged
// into a parent span still appear as CALL destinations.
inline std::vector<uint64_t> collect_rel32_call_targets(uint64_t start, size_t size) {
    std::vector<uint64_t> out;
    if (start == 0 || size < 5) {
        return out;
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(start);
    for (size_t i = 0; i + 5 <= size;) {
        const uint8_t op = bytes[i];
        if (op == 0xE8 || op == 0xE9) {
            int32_t rel = 0;
            std::memcpy(&rel, bytes + i + 1, sizeof(rel));
            out.push_back(static_cast<uint64_t>(
                    static_cast<int64_t>(start + i + 5) + static_cast<int64_t>(rel)));
            i += 5;
            continue;
        }
        ++i;
    }
    return out;
}

inline void erase_claimed(std::unordered_set<uint64_t> &targets,
                          const std::unordered_set<uint64_t> &claimed) {
    for (auto it = targets.begin(); it != targets.end();) {
        if (claimed.count(*it)) {
            it = targets.erase(it);
        } else {
            ++it;
        }
    }
}

// Intersection of per-caller unclaimed CALL-target sets. Empty if no
// common target. Callers should size-fingerprint when size() > 1.
// Bytes from entry until CALL/JMP-rel32, RIP-relative, or abs imm32.
// Used to disambiguate eh_frame-split callers that share a callee.
inline size_t reloc_free_prefix_len(const uint8_t *p, size_t n, size_t cap = 16) {
    if (!p || n == 0) {
        return 0;
    }
    const size_t lim = n < cap ? n : cap;
    size_t i = 0;
    while (i < lim) {
        if (p[i] == 0xE8 || p[i] == 0xE9) {
            break;
        }
        if (p[i] >= 0xB8 && p[i] <= 0xBF) {
            break;
        }
        if (i + 2 < lim && (p[i] == 0x48 || p[i] == 0x4c) &&
            (p[i + 1] == 0x8d || p[i + 1] == 0x8b) &&
            (p[i + 2] & 0xC7) == 0x05) {
            break;
        }
        ++i;
    }
    return i;
}

// Keep candidates whose first E8/E9 lands on `callee` (loadbuffer calls
// lua_load first; loadstring calls strlen first).
inline std::vector<uint64_t>
filter_by_first_rel32_callee(const std::vector<uint64_t> &candidates, uint64_t callee,
                             size_t walk = 64) {
    if (callee == 0) {
        return candidates;
    }
    std::vector<uint64_t> hit;
    for (auto c: candidates) {
        const auto tgts = collect_rel32_call_targets(c, walk);
        if (!tgts.empty() && tgts.front() == callee) {
            hit.push_back(c);
        }
    }
    return hit.empty() ? candidates : hit;
}

inline std::vector<uint64_t>
filter_by_reloc_free_prefix(const std::vector<uint64_t> &candidates, const uint8_t *train,
                            size_t train_size) {
    const size_t plen = reloc_free_prefix_len(train, train_size);
    if (plen < 4 || !train) {
        return candidates;
    }
    std::vector<uint64_t> hit;
    for (auto c: candidates) {
        const auto *cb = reinterpret_cast<const uint8_t *>(c);
        if (reloc_free_prefix_len(cb, plen + 8) >= plen &&
            std::memcmp(cb, train, plen) == 0) {
            hit.push_back(c);
        }
    }
    return hit.empty() ? candidates : hit;
}

inline std::vector<uint64_t>
intersect_callee_sets(const std::vector<std::unordered_set<uint64_t>> &sets) {
    if (sets.empty()) {
        return {};
    }
    std::unordered_set<uint64_t> acc = sets.front();
    for (size_t i = 1; i < sets.size(); ++i) {
        std::unordered_set<uint64_t> next;
        next.reserve(acc.size());
        for (auto t: acc) {
            if (sets[i].count(t)) {
                next.insert(t);
            }
        }
        acc.swap(next);
        if (acc.empty()) {
            break;
        }
    }
    return {acc.begin(), acc.end()};
}

} // namespace function_relocation
