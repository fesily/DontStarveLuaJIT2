// Caller-graph seed: intersect unclaimed CALL targets across resolved
// callers. lua_isnumber is the unique common callee of luaL_checknumber
// and luaL_checkinteger even when Nucleus merged it into a parent span.

#include "GraphSeed.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <unordered_set>
#include <vector>

#define REQUIRE(cond)                                                                          \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);  \
            std::abort();                                                                      \
        }                                                                                      \
    } while (0)

static void test_rel32_collects_call_target() {
    unsigned char buf[16] = {};
    // e8 06 00 00 00  nop...  → call to buf+5+6 = buf+11
    buf[0] = 0xe8;
    buf[1] = 0x06;
    buf[2] = 0x00;
    buf[3] = 0x00;
    buf[4] = 0x00;
    const auto start = reinterpret_cast<uint64_t>(buf);
    const auto tgts = function_relocation::collect_rel32_call_targets(start, sizeof(buf));
    REQUIRE(tgts.size() == 1);
    REQUIRE(tgts[0] == start + 11);
}

static void test_intersect_unique_common_callee() {
    // checknumber callees: tonumber, isnumber, argerror
    // checkinteger callees: tointeger, isnumber, argerror
    // claimed: tonumber, tointeger, argerror
    // intersection of unclaimed = {isnumber}
    const uint64_t tonumber = 0x1000;
    const uint64_t isnumber = 0x1100;
    const uint64_t tointeger = 0x1200;
    const uint64_t argerror = 0x1300;
    std::unordered_set<uint64_t> claimed{tonumber, tointeger, argerror};

    std::unordered_set<uint64_t> checknumber{tonumber, isnumber, argerror};
    std::unordered_set<uint64_t> checkinteger{tointeger, isnumber, argerror};
    function_relocation::erase_claimed(checknumber, claimed);
    function_relocation::erase_claimed(checkinteger, claimed);

    const auto hit = function_relocation::intersect_callee_sets({checknumber, checkinteger});
    REQUIRE(hit.size() == 1);
    REQUIRE(hit[0] == isnumber);
}

static void test_intersect_empty_when_inlined() {
    std::unordered_set<uint64_t> a{0x1, 0x2};
    std::unordered_set<uint64_t> b{0x3, 0x4};
    const auto hit = function_relocation::intersect_callee_sets({a, b});
    REQUIRE(hit.empty());
}

static void test_intersect_two_commons_need_fingerprint() {
    std::unordered_set<uint64_t> a{0x10, 0x20, 0x30};
    std::unordered_set<uint64_t> b{0x20, 0x30, 0x40};
    auto hit = function_relocation::intersect_callee_sets({a, b});
    std::sort(hit.begin(), hit.end());
    REQUIRE(hit.size() == 2);
    REQUIRE(hit[0] == 0x20);
    REQUIRE(hit[1] == 0x30);
}

int main() {
    test_rel32_collects_call_target();
    test_intersect_unique_common_callee();
    test_intersect_empty_when_inlined();
    test_intersect_two_commons_need_fingerprint();
    std::puts("test_graph_seed: ok");
    return 0;
}
