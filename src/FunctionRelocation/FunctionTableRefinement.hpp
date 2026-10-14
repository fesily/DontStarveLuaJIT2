#pragma once

#include "FunctionTable.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace function_relocation::detail {

    // Preserve authoritative extents and supplement every uncovered part of the
    // fallback spans. All ranges are half-open; fallback fragments must not overlap
    // authoritative bytes, so they cannot override authoritative entry lookup.
    inline FunctionTable refine_function_table(const FunctionTable &fallback,
                                              std::vector<FunctionSpan> authoritative) {
        authoritative.erase(std::remove_if(authoritative.begin(), authoritative.end(),
                                          [](const FunctionSpan &span) { return span.end <= span.start; }),
                            authoritative.end());
        if (authoritative.empty()) return fallback;
        std::sort(authoritative.begin(), authoritative.end(),
                  [](const FunctionSpan &a, const FunctionSpan &b) { return a.start < b.start; });

        // Merge only the coverage used for subtraction. Keep the original extents
        // in the output, including boundaries between adjacent or overlapping FDEs.
        std::vector<FunctionSpan> coverage;
        coverage.reserve(authoritative.size());
        for (const auto &span: authoritative) {
            if (coverage.empty() || span.start > coverage.back().end) {
                coverage.push_back(span);
            } else {
                coverage.back().end = (std::max)(coverage.back().end, span.end);
            }
        }

        std::vector<FunctionSpan> refined = std::move(authoritative);
        for (const auto &span: fallback.spans()) {
            auto it = std::upper_bound(coverage.begin(), coverage.end(), span.start,
                                       [](uint64_t address, const FunctionSpan &range) { return address < range.end; });
            uint64_t cursor = span.start;
            for (; it != coverage.end() && it->start < span.end; ++it) {
                if (cursor < it->start) refined.push_back({cursor, it->start});
                cursor = (std::max)(cursor, it->end);
                if (cursor >= span.end) break;
            }
            if (cursor < span.end) refined.push_back({cursor, span.end});
        }

        // Batch-sort before inserting into FunctionTable to avoid repeatedly
        // shifting all later authoritative ranges for each fallback fragment.
        std::sort(refined.begin(), refined.end(),
                  [](const FunctionSpan &a, const FunctionSpan &b) {
                      return a.start < b.start || (a.start == b.start && a.end < b.end);
                  });
        // Different Nucleus bodies can yield identical uncovered fragments.
        // One copy preserves lookup and coverage without duplicate candidates.
        refined.erase(std::unique(refined.begin(), refined.end(),
                                  [](const FunctionSpan &a, const FunctionSpan &b) {
                                      return a.start == b.start && a.end == b.end;
                                  }),
                      refined.end());
        FunctionTable result;
        for (const auto &span: refined) result.add(span);
        return result;
    }

}// namespace function_relocation::detail
