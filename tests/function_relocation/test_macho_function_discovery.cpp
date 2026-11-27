// Mach-O function entry discovery: the loaded test executable's own
// LC_FUNCTION_STARTS table through the production dispatch, plus the shared
// ULEB128 decoder with synthetic blobs (bounds, termination, overflow).
//
// The synthetic case exists because the decoder's origin and ULEB boundary
// behaviour cannot be observed through a toolchain-produced table.

#include "FunctionDiscovery.hpp"
#include "FunctionRanges.hpp"
#include "ModuleSections.hpp"
#include "support/fr_context_env.hpp"

#include <doctest/doctest.h>

#if defined(__APPLE__)

#include <algorithm>
#include <array>
#include <cstdint>
#include <vector>

namespace {

    // Two non-exported functions with distinct bodies: both must appear as
    // separate entries of the function-starts table.
    __attribute__((noinline, used)) int ds_macho_probe_one(int value) {
        return value * 3 + 1;
    }

    __attribute__((noinline, used)) int ds_macho_probe_two(int value) {
        return value ^ 0x5a5a;
    }

    const function_relocation::FunctionSpan *span_at(const function_relocation::ModuleSections &module,
                                                     uint64_t address) {
        for (const auto &span: module.function_table.spans()) {
            if (span.start == address) return &span;
        }
        return nullptr;
    }

    bool decode(const std::vector<uint8_t> &blob, GumMemoryRange text,
                std::vector<function_relocation::FunctionSpan> &spans) {
        return function_relocation::detail::decode_macho_function_starts(
                0x1000, text, std::span<const uint8_t>{blob.data(), blob.size()}, spans);
    }

}// namespace

TEST_CASE("test_macho_function_discovery/loaded_module_entries") {
    REQUIRE(ensure_reloc_context());
    function_relocation::ModuleSections module{};
    REQUIRE(function_relocation::get_module_sections(nullptr, module));
    REQUIRE(function_relocation::discover_module_functions(module));

    const auto one = reinterpret_cast<uintptr_t>(&ds_macho_probe_one);
    const auto two = reinterpret_cast<uintptr_t>(&ds_macho_probe_two);
    REQUIRE_NE(one, two);
    const auto *span_one = span_at(module, one);
    const auto *span_two = span_at(module, two);
    REQUIRE_NE(span_one, nullptr);
    REQUIRE_NE(span_two, nullptr);
    REQUIRE_EQ(span_one->start, one);
    REQUIRE_EQ(span_two->start, two);
    REQUIRE_GT(span_one->end, span_one->start);
    REQUIRE_GT(span_two->end, span_two->start);

    // Strictly increasing, and every end is the next entry or __text end.
    const auto &spans = module.function_table.spans();
    REQUIRE_GT(spans.size(), 1);
    const uint64_t text_end = module.text.base_address + module.text.size;
    for (size_t i = 0; i < spans.size(); ++i) {
        REQUIRE_GT(spans[i].end, spans[i].start);
        if (i + 1 < spans.size()) {
            REQUIRE_LT(spans[i].start, spans[i + 1].start);
            REQUIRE_EQ(spans[i].end, spans[i + 1].start);
        } else {
            REQUIRE_EQ(spans[i].end, text_end);
        }
    }
}

TEST_CASE("test_macho_function_discovery/uleb_blob") {
    const GumMemoryRange text{0x1080, 0x40};
    std::vector<function_relocation::FunctionSpan> spans;

    // 0x20 -> image base + 0x20 (outside __text, dropped); +0x65 -> 0x1085;
    // +0x05 -> 0x108a; 0x00 terminates.
    REQUIRE(decode({0x20, 0x65, 0x05, 0x00}, text, spans));
    REQUIRE_EQ(spans.size(), 2);
    CHECK_EQ(spans[0].start, 0x1085);
    CHECK_EQ(spans[0].end, 0x108a);
    CHECK_EQ(spans[1].start, 0x108a);
    CHECK_EQ(spans[1].end, 0x10c0);

    // Truncated value (continuation bit with no following byte).
    CHECK_FALSE(decode({0x80}, text, spans));
    REQUIRE(spans.empty());
    // Missing zero terminator.
    CHECK_FALSE(decode({0x20, 0x65, 0x05}, text, spans));
    // A ten-byte item whose payload overflows 64 bits.
    CHECK_FALSE(decode({0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x00}, text,
                       spans));
    // No entry inside __text.
    CHECK_FALSE(decode({0x01, 0x00}, text, spans));
}

#else

TEST_CASE("test_macho_function_discovery/apple_only") {
    CHECK(true);
}

#endif
