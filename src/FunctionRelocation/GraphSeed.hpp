#pragma once

#include <cstdint>
#include <cstring>
#include <unordered_set>
#include <vector>
#include "export.hpp"

namespace function_relocation {
    struct ModuleSections;

    // Decode direct CALL/JMP targets at instruction boundaries. Return raw targets
    // so exports inside a coarser FunctionTable span remain distinguishable.
    FUNCTION_RELOCATION_API std::vector<uint64_t> collect_rel32_call_targets(uint64_t start, size_t size);

    // Resolve module PLT/GOT thunks to exact callees. Preserve call order and
    // leave unbound thunks unchanged; graph seeds must select in-text targets.
    FUNCTION_RELOCATION_API std::vector<uint64_t> collect_rel32_call_targets(
            const ModuleSections &module, uint64_t start, size_t size);

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
FUNCTION_RELOCATION_API size_t reloc_free_prefix_len(const uint8_t *p, size_t n, size_t cap = 16);

// Keep candidates whose first decoded direct CALL/JMP lands on `callee` (loadbuffer calls
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
filter_by_first_rel32_callee(const ModuleSections &module, const std::vector<uint64_t> &candidates,
                             uint64_t callee, size_t walk = 64) {
    if (callee == 0) return candidates;
    std::vector<uint64_t> hit;
    for (auto candidate: candidates) {
        const auto targets = collect_rel32_call_targets(module, candidate, walk);
        if (!targets.empty() && targets.front() == callee) hit.push_back(candidate);
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
