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
