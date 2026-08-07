#include "FunctionRanges.hpp"
#include <algorithm>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace function_relocation {

const FuncRange* find_range_containing(const std::vector<FuncRange>& ranges, uintptr_t addr) {
    for (const auto& r : ranges) {
        if (r.start <= addr && addr < r.end)
            return &r;
    }
    return nullptr;
}

bool enumerate_function_ranges_win(const ModuleSections& m, std::vector<FuncRange>& out) {
    out.clear();
#ifndef _WIN32
    (void)m;
    return false;
#else
    if (m.pdata.base_address == 0 || m.pdata.size < sizeof(RUNTIME_FUNCTION))
        return false;

    const auto image_base = m.details.range.base_address;
    auto* ptr = reinterpret_cast<const uint8_t*>(m.pdata.base_address);
    const auto* end = ptr + m.pdata.size;

    uintptr_t logical_begin = 0;
    uintptr_t logical_end = 0;
    bool open = false;

    auto flush = [&]() {
        if (!open) return;
        FuncRange r{};
        r.start = logical_begin;
        r.end = logical_end;
        r.source = FuncRange::Source::Pdata;
        out.push_back(r);
        open = false;
    };

    for (; ptr + sizeof(RUNTIME_FUNCTION) <= end; ptr += sizeof(RUNTIME_FUNCTION)) {
        const auto* rf = reinterpret_cast<const RUNTIME_FUNCTION*>(ptr);
        if (rf->BeginAddress == 0)
            break;

        const uintptr_t b = image_base + rf->BeginAddress;
        const uintptr_t e = image_base + rf->EndAddress;

        // Skip entries that do not land in text (best-effort).
        if (!m.in_text(b) || e < b) {
            continue;
        }

        if (open && b == logical_end) {
            // Adjacent chain: extend end.
            logical_end = e;
            continue;
        }

        flush();
        logical_begin = b;
        logical_end = e;
        open = true;
    }
    flush();

    std::sort(out.begin(), out.end(),
              [](const FuncRange& a, const FuncRange& b) { return a.start < b.start; });
    // Dedupe same start: keep longer end.
    std::vector<FuncRange> dedup;
    for (const auto& r : out) {
        if (!dedup.empty() && dedup.back().start == r.start) {
            dedup.back().end = std::max(dedup.back().end, r.end);
        } else {
            dedup.push_back(r);
        }
    }
    out.swap(dedup);
    return !out.empty();
#endif
}

} // namespace function_relocation
