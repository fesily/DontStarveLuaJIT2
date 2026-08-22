#include "FunctionRanges.hpp"
#include "ModuleSections.hpp"

// Keep checks active under RelWithDebInfo (NDEBUG would strip assert).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdio>
#include <cstdlib>

using function_relocation::FuncRange;
using function_relocation::ModuleSections;
using function_relocation::enumerate_function_ranges_win;
using function_relocation::find_range_containing;

#define REQUIRE(cond)                                                                          \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__); \
            std::abort();                                                                      \
        }                                                                                      \
    } while (0)

// Minimal RUNTIME_FUNCTION: Begin, End, UnwindInfo RVA (unused in v1 merge-by-adjacent).
#pragma pack(push, 1)
struct RtFn {
    uint32_t BeginAddress;
    uint32_t EndAddress;
    uint32_t UnwindData;
};
#pragma pack(pop)
static_assert(sizeof(RtFn) == 12);

static ModuleSections make_module(uintptr_t image_base, uintptr_t text_rva, size_t text_size,
                                  const RtFn* table, size_t count) {
    ModuleSections m{};
    m.details.range.base_address = image_base;
    m.details.range.size = text_rva + text_size + 0x1000;
    m.text.base_address = image_base + text_rva;
    m.text.size = text_size;
    m.pdata.base_address = reinterpret_cast<uintptr_t>(table);
    m.pdata.size = count * sizeof(RtFn);
    return m;
}

static void test_two_independent() {
    // image_base 0x140000000; text at rva 0x1000 size 0x5000
    const uintptr_t base = 0x140000000ull;
    RtFn table[] = {
        {0x1000, 0x1100, 0},
        {0x1200, 0x1300, 0},
        {0, 0, 0}, // terminator
    };
    auto m = make_module(base, 0x1000, 0x5000, table, 3);
    std::vector<FuncRange> out;
    REQUIRE(enumerate_function_ranges_win(m, out));
    REQUIRE(out.size() == 2);
    REQUIRE(out[0].start == base + 0x1000);
    REQUIRE(out[0].end == base + 0x1100);
    REQUIRE(out[1].start == base + 0x1200);
    REQUIRE(out[1].end == base + 0x1300);
}

static void test_chain_merge() {
    const uintptr_t base = 0x140000000ull;
    // r1.End == r2.Begin → one logical function
    RtFn table[] = {
        {0x2000, 0x2100, 0},
        {0x2100, 0x2200, 0},
        {0, 0, 0},
    };
    auto m = make_module(base, 0x1000, 0x5000, table, 3);
    std::vector<FuncRange> out;
    REQUIRE(enumerate_function_ranges_win(m, out));
    REQUIRE(out.size() == 1);
    REQUIRE(out[0].start == base + 0x2000);
    REQUIRE(out[0].end == base + 0x2200);
}

static void test_terminator() {
    const uintptr_t base = 0x140000000ull;
    RtFn table[] = {
        {0x1000, 0x1080, 0},
        {0, 0, 0},
        {0x3000, 0x3100, 0}, // must not be read
    };
    auto m = make_module(base, 0x1000, 0x5000, table, 3);
    std::vector<FuncRange> out;
    REQUIRE(enumerate_function_ranges_win(m, out));
    REQUIRE(out.size() == 1);
    REQUIRE(out[0].start == base + 0x1000);
}

static void test_empty_pdata() {
    ModuleSections m{};
    m.details.range.base_address = 0x140000000ull;
    m.details.range.size = 0x10000;
    m.text.base_address = 0x140001000ull;
    m.text.size = 0x1000;
    m.pdata = {0, 0};
    std::vector<FuncRange> out;
    REQUIRE(!enumerate_function_ranges_win(m, out));
    REQUIRE(out.empty());
}

static void test_find_containing() {
    std::vector<FuncRange> ranges = {
        {0x1000, 0x1100, FuncRange::Source::Pdata},
        {0x2000, 0x2200, FuncRange::Source::Pdata},
    };
    REQUIRE(find_range_containing(ranges, 0x1000)->start == 0x1000);
    REQUIRE(find_range_containing(ranges, 0x10FF)->start == 0x1000);
    REQUIRE(find_range_containing(ranges, 0x2100)->start == 0x2000);
    REQUIRE(find_range_containing(ranges, 0x1100) == nullptr);
    REQUIRE(find_range_containing(ranges, 0x50) == nullptr);
}

int main() {
    test_two_independent();
    test_chain_merge();
    test_terminator();
    test_empty_pdata();
    test_find_containing();
    std::puts("function_ranges: all passed");
    return 0;
}
