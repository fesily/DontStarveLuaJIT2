// Unit tests for the micro-window pattern generator and multi-hit same-entry
// resolver (plan function-relocation-match-v2, todo 2).
//
// Header-only logic: no frida-gum, no function_relocation link required.
// Exercises:
//   * CALL/JMP split: generator yields zero windows whose pattern contains the
//     CALL opcode bytes as an interior instruction (the call insn is dropped).
//   * Same-entry multi-hit: votes for a single entry E with two distinct raw
//     match addresses -> accept E; pattern_offset = E - min(matches).
//   * Ambiguous entries with equal votes and no margin -> fail-closed null;
//     SignatureInfo is left unchanged on reject.

#include "MicroWindow.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace function_relocation::micro_window;
using function_relocation::match_policy::AcceptResult;

#define REQUIRE(cond)                                                                          \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);  \
            std::abort();                                                                      \
        }                                                                                      \
    } while (0)

static MicroInsn mk(uint64_t addr, const char *hex, float weight = 1.0f) {
    MicroInsn m;
    m.address = addr;
    m.size = 3;
    m.splits = false;
    m.hex = hex;
    m.hex += ' ';
    m.weight = weight;
    return m;
}

static MicroInsn mkcall(uint64_t addr) {
    MicroInsn m;
    m.address = addr;
    m.size = 5;
    m.splits = true;
    m.hex = "e8 ?? ?? ?? ?? ";
    m.weight = 0.0f;
    return m;
}

static MicroInsn mkjmp(uint64_t addr) {
    MicroInsn m;
    m.address = addr;
    m.size = 5;
    m.splits = true;
    m.hex = "e9 ?? ?? ?? ?? ";
    m.weight = 0.0f;
    return m;
}

// Synthetic body: 8 unique movs, one CALL helper, then 8 unique movs.
// The generator must NOT emit any window whose pattern contains the CALL
// opcode ("e8") as an interior instruction.
static void test_call_not_interior() {
    std::vector<MicroInsn> body;
    uint64_t a = 0x1000;
    for (int k = 0; k < 8; ++k) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "48 89 %02x", k);
        body.push_back(mk(a, buf, 1.0f));
        a += 3;
    }
    body.push_back(mkcall(a)); // CALL at 0x1018
    a += 5;
    for (int k = 0; k < 8; ++k) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "48 8b %02x", k);
        body.push_back(mk(a, buf, 1.0f));
        a += 3;
    }

    auto windows = generate_micro_windows(body, 0x1000);
    REQUIRE(!windows.empty());
    for (const auto &w : windows) {
        // No window pattern may contain the CALL opcode "e8".
        REQUIRE(w.pattern.find("e8") == std::string::npos);
    }
    // Sanity: both segments are >=5 insns, so windows exist on both sides.
    // Before-call windows contain "48 89" (mov store); after-call "48 8b" (mov load).
    bool has_before = false, has_after = false;
    for (const auto &w : windows) {
        if (w.pattern.find("48 89") != std::string::npos) has_before = true;
        if (w.pattern.find("48 8b") != std::string::npos) has_after = true;
    }
    REQUIRE(has_before);
    REQUIRE(has_after);
}

// Same entry, two distinct raw match addresses, three votes -> score 3.0 >= SCORE_T.
// Accept entry E; pattern_offset = E - min(matches).
static void test_same_entry_accept() {
    const uint64_t E = 0x2000;
    std::vector<HitVote> votes = {
        {0x2010, E},
        {0x2020, E},
        {0x2010, E}, // duplicate address from a second window -> 3 votes, 2 distinct
    };
    auto r = resolve_multi_hit_entry(votes);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E);
    REQUIRE(r->chosen_raw_match == 0x2010); // earliest raw match
    const int pattern_offset = static_cast<int>(
        static_cast<intptr_t>(r->entry) - static_cast<intptr_t>(r->chosen_raw_match));
    REQUIRE(pattern_offset == static_cast<int>(0x2000 - 0x2010));
}

// Two entries with equal votes and no margin -> fail-closed null.
// SignatureInfo would be left unchanged (the production path only writes on accept).
static void test_ambiguous_fail_closed() {
    const uint64_t E1 = 0x1000;
    const uint64_t E2 = 0x3000;
    std::vector<HitVote> votes = {
        {0x1010, E1}, {0x1010, E1}, {0x1010, E1},
        {0x3010, E2}, {0x3010, E2}, {0x3010, E2},
    };
    auto r = resolve_multi_hit_entry(votes);
    REQUIRE(!r.has_value());
}

// Below SCORE_T with a single entry -> reject (vote=2 -> score 2.0 < 3.0).
static void test_below_threshold_reject() {
    const uint64_t E = 0x4000;
    std::vector<HitVote> votes = {{0x4010, E}, {0x4020, E}};
    auto r = resolve_multi_hit_entry(votes);
    REQUIRE(!r.has_value());
}

// Unconditional JMP also splits (not a separator for interior inclusion).
static void test_jmp_splits() {
    std::vector<MicroInsn> body;
    uint64_t a = 0x5000;
    for (int k = 0; k < 6; ++k) {
        body.push_back(mk(a, "48 89 0a", 1.0f));
        a += 3;
    }
    body.push_back(mkjmp(a));
    a += 5;
    for (int k = 0; k < 6; ++k) {
        body.push_back(mk(a, "48 8b 0a", 1.0f));
        a += 3;
    }
    auto windows = generate_micro_windows(body, 0x5000);
    REQUIRE(!windows.empty());
    for (const auto &w : windows) {
        REQUIRE(w.pattern.find("e9") == std::string::npos);
    }
}

// Window with <5 non-wildcard bytes is skipped (all-wildcard insns).
static void test_skip_low_distinguishing() {
    std::vector<MicroInsn> body;
    uint64_t a = 0x6000;
    for (int k = 0; k < 10; ++k) {
        MicroInsn m;
        m.address = a;
        m.size = 2;
        m.splits = false;
        m.hex = "?? ?? ";
        m.weight = 1.0f;
        body.push_back(m);
        a += 2;
    }
    auto windows = generate_micro_windows(body, 0x6000);
    REQUIRE(windows.empty());
}

// Higher-weight regions are emitted first (sort by weight desc).
static void test_weight_ordering() {
    std::vector<MicroInsn> body;
    uint64_t a = 0x7000;
    for (int k = 0; k < 7; ++k) {
        body.push_back(mk(a, "48 89 0a", (k == 3) ? 5.0f : 1.0f));
        a += 3;
    }
    auto windows = generate_micro_windows(body, 0x7000);
    REQUIRE(!windows.empty());
    // Every window containing the high-weight insn has weight 5.0f; windows
    // without it have weight 1.0f. The first emitted window has the max weight.
    REQUIRE(windows.front().weight >= 5.0f);
}

int main(int argc, char **argv) {
    std::string sel = (argc > 1) ? argv[1] : "all";
    if (sel == "all" || sel == "call-interior") test_call_not_interior();
    if (sel == "all" || sel == "same-entry") test_same_entry_accept();
    if (sel == "all" || sel == "ambiguous") test_ambiguous_fail_closed();
    if (sel == "all" || sel == "below-threshold") test_below_threshold_reject();
    if (sel == "all" || sel == "jmp-splits") test_jmp_splits();
    if (sel == "all" || sel == "low-distinguishing") test_skip_low_distinguishing();
    if (sel == "all" || sel == "weight-ordering") test_weight_ordering();
    std::puts("test_micro_windows: ok");
    return 0;
}
