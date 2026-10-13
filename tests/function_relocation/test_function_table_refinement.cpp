#include "FunctionTableRefinement.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <vector>

using function_relocation::FunctionSpan;
using function_relocation::FunctionTable;

#define REQUIRE(cond) \
    do { \
        if (!(cond)) { \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            std::abort(); \
        } \
    } while (0)

static bool same_span(const FunctionSpan &a, const FunctionSpan &b) {
    return a.start == b.start && a.end == b.end;
}

static bool covers(const std::vector<FunctionSpan> &spans, uint64_t address) {
    return std::any_of(spans.begin(), spans.end(), [&](const auto &span) {
        return span.start <= address && address < span.end;
    });
}

static void check_refinement(const std::vector<FunctionSpan> &fallback_spans,
                             const std::vector<FunctionSpan> &authoritative,
                             std::vector<FunctionSpan> expected) {
    FunctionTable fallback;
    for (const auto &span: fallback_spans) fallback.add(span);
    auto result = function_relocation::detail::refine_function_table(fallback, authoritative);

    auto actual = result.spans();
    auto order = [](const FunctionSpan &a, const FunctionSpan &b) {
        return a.start < b.start || (a.start == b.start && a.end < b.end);
    };
    std::sort(actual.begin(), actual.end(), order);
    std::sort(expected.begin(), expected.end(), order);
    REQUIRE(actual.size() == expected.size());
    for (size_t i = 0; i < actual.size(); ++i) REQUIRE(same_span(actual[i], expected[i]));

    std::vector<uint64_t> probes{0, std::numeric_limits<uint64_t>::max()};
    for (const auto &spans: {fallback_spans, authoritative, actual}) {
        for (const auto &span: spans) {
            probes.push_back(span.start);
            probes.push_back(span.end);
            if (span.start > 0) probes.push_back(span.start - 1);
            if (span.end > 0) probes.push_back(span.end - 1);
        }
    }
    for (uint64_t address: probes) {
        const auto *span = result.span_containing(address);
        // The original union of covered bytes must be preserved exactly.
        REQUIRE((span != nullptr) == (covers(fallback_spans, address) || covers(authoritative, address)));
        if (covers(authoritative, address)) {
            REQUIRE(span != nullptr);
            REQUIRE(std::any_of(authoritative.begin(), authoritative.end(),
                                [&](const auto &fde) { return same_span(*span, fde); }));
        }
    }
    for (const auto &span: actual) {
        if (std::any_of(authoritative.begin(), authoritative.end(),
                        [&](const auto &fde) { return same_span(span, fde); })) continue;
        for (const auto &fde: authoritative) {
            if (fde.end <= fde.start) continue;
            REQUIRE(span.end <= fde.start || span.start >= fde.end);
        }
    }
}

int main() {
    // Regression: a Nucleus start inside an FDE must not lose the outside tail.
    check_refinement({{100, 200}}, {{80, 150}}, {{80, 150}, {150, 200}});
    check_refinement({{100, 200}}, {{150, 220}}, {{100, 150}, {150, 220}});
    check_refinement({{100, 200}}, {{120, 140}}, {{100, 120}, {120, 140}, {140, 200}});
    check_refinement({{100, 300}}, {{80, 140}, {160, 200}, {240, 320}},
                     {{80, 140}, {140, 160}, {160, 200}, {200, 240}, {240, 320}});

    // Full coverage, disjoint spans and exactly touching half-open boundaries.
    check_refinement({{100, 200}}, {{80, 220}}, {{80, 220}});
    check_refinement({{100, 200}}, {{300, 400}}, {{100, 200}, {300, 400}});
    check_refinement({{100, 200}}, {{80, 100}, {200, 220}}, {{80, 100}, {100, 200}, {200, 220}});
    check_refinement({{100, 200}}, {{100, 150}, {150, 200}}, {{100, 150}, {150, 200}});
    check_refinement({{100, 200}}, {}, {{100, 200}});
    check_refinement({}, {{100, 200}}, {{100, 200}});

    // Unsorted, overlapping, nested and duplicate FDEs retain their distinct
    // exact extents while their combined coverage is subtracted from Nucleus.
    check_refinement({{100, 300}}, {{180, 240}, {140, 180}, {120, 200}, {140, 180}},
                     {{100, 120}, {120, 200}, {140, 180}, {180, 240}, {240, 300}});
    check_refinement({{100, 200}, {180, 260}}, {{150, 220}}, {{100, 150}, {150, 220}, {220, 260}});
    check_refinement({{100, 200}, {120, 180}}, {{140, 160}},
                     {{100, 140}, {120, 140}, {140, 160}, {160, 180}, {160, 200}});
    check_refinement({{100, 200}, {120, 200}}, {{80, 150}}, {{80, 150}, {150, 200}});

    // Invalid extents are ignored, and subtraction does not add to addresses.
    check_refinement({{100, 200}}, {{120, 120}, {200, 100}}, {{100, 200}});
    check_refinement({{100, 200}}, {{120, 120}, {140, 160}}, {{100, 140}, {140, 160}, {160, 200}});
    constexpr uint64_t high = std::numeric_limits<uint64_t>::max();
    check_refinement({{high - 20, high}}, {{high - 30, high - 10}},
                     {{high - 30, high - 10}, {high - 10, high}});

    std::puts("test_function_table_refinement: ok");
    return 0;
}
