// Unit tests for soft multi-feature scoring (plan function-relocation-match-v2,
// todo 3). Exercises the feature-aware resolve_multi_hit_entry overload and
// the pure score component functions. Header-only: no frida-gum, no
// function_relocation link required.
//
// Scenarios:
//   1. twin_identical: two entries with identical features → equal scores →
//      gap 0 < SCORE_M → FAIL-CLOSED.
//   2. twin_distinct_strings: two entries, one matches train consts → high
//      W_CONST margin → accept correct entry.
//   3. sole_below_threshold: single entry with score < SCORE_T → reject.
//   4. size_band_bonus: size in band adds +2.0 pushing score over SCORE_T.

#include "MicroWindow.hpp"

#include <cstdio>
#include <cstdlib>

using namespace function_relocation::micro_window;
namespace mp = function_relocation::match_policy;

#define REQUIRE(cond)                                                                          \
    do {                                                                                       \
        if (!(cond)) {                                                                         \
            std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);  \
            std::abort();                                                                      \
        }                                                                                      \
    } while (0)

static mp::FunctionFeatures make_feats(std::vector<std::string> consts,
                                       std::vector<int64_t> imms,
                                       uint64_t size) {
    mp::FunctionFeatures f;
    f.consts = std::move(consts);
    f.imms = std::move(imms);
    f.size = size;
    return f;
}

// --- Pure score component tests ---

static void test_vote_component() {
    REQUIRE(mp::vote_component(0) == 0.0f);
    REQUIRE(mp::vote_component(3) == 3.0f);
    REQUIRE(mp::vote_component(8) == 8.0f);
    REQUIRE(mp::vote_component(100) == 8.0f); // capped
}

static void test_const_component() {
    // Exact match: 10.0 * 1/1
    REQUIRE(mp::const_component({"a"}, {"a"}) == 10.0f);
    // 2 of 3 match: 10.0 * 2/3
    REQUIRE(mp::const_component({"a", "b", "c"}, {"a", "b", "z"}) ==
            (10.0f * 2.0f / 3.0f));
    // Train empty → 0
    REQUIRE(mp::const_component({}, {"a"}) == 0.0f);
    // No overlap → 0
    REQUIRE(mp::const_component({"a"}, {"b"}) == 0.0f);
}

static void test_imm_component() {
    REQUIRE(mp::imm_component({0x10}, {0x10}) == 4.0f);
    REQUIRE(mp::imm_component({0x10, 0x20}, {0x10}) == 4.0f * 0.5f);
    REQUIRE(mp::imm_component({}, {0x10}) == 0.0f);
    REQUIRE(mp::imm_component({0x10}, {0x20}) == 0.0f);
}

static void test_size_component() {
    // In band [50, 300]
    REQUIRE(mp::size_component(100, 50) == 2.0f);
    REQUIRE(mp::size_component(100, 300) == 2.0f);
    REQUIRE(mp::size_component(100, 150) == 2.0f);
    // Out of band
    REQUIRE(mp::size_component(100, 49) == 0.0f);
    REQUIRE(mp::size_component(100, 301) == 0.0f);
    // Train size 0 → 0
    REQUIRE(mp::size_component(0, 100) == 0.0f);
}

// --- Integration tests via resolve_multi_hit_entry with features ---

// 1. Twin identical bodies, equal features → equal scores → FAIL-CLOSED.
static void test_twin_identical_reject() {
    const uint64_t E1 = 0x1000;
    const uint64_t E2 = 0x2000;
    auto train = make_feats({"a", "b"}, {0x10}, 100);
    auto tgt = make_feats({"a", "b"}, {0x10}, 100); // identical

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E1] = tgt;
    target_feats[E2] = tgt;

    // Equal votes for both entries → equal total scores → gap 0 < SCORE_M.
    std::vector<HitVote> votes = {
        {0x1010, E1}, {0x1020, E1}, {0x1030, E1}, {0x1040, E1},
        {0x2010, E2}, {0x2020, E2}, {0x2030, E2}, {0x2040, E2},
    };
    auto r = resolve_multi_hit_entry(votes, train, target_feats);
    REQUIRE(!r.has_value());
}

// 2. Twin with distinct strings: correct entry has high W_CONST → accept.
static void test_twin_distinct_strings_accept() {
    const uint64_t E_correct = 0x1000;
    const uint64_t E_wrong = 0x2000;
    auto train = make_feats({"alpha", "beta", "gamma"}, {0x10}, 100);
    auto tgt_correct = make_feats({"alpha", "beta", "gamma"}, {0x10}, 100);
    auto tgt_wrong = make_feats({"delta", "epsilon"}, {0x20}, 100);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E_correct] = tgt_correct;
    target_feats[E_wrong] = tgt_wrong;

    // Both get equal votes; only E_correct gets W_CONST+W_IMM bonus.
    std::vector<HitVote> votes = {
        {0x1010, E_correct}, {0x1020, E_correct}, {0x1030, E_correct}, {0x1040, E_correct},
        {0x2010, E_wrong}, {0x2020, E_wrong}, {0x2030, E_wrong}, {0x2040, E_wrong},
    };
    auto r = resolve_multi_hit_entry(votes, train, target_feats);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E_correct);
    // E_correct score = 4(vote) + 10(const) + 4(imm) + 2(size) = 20.0
    REQUIRE(r->score == 20.0f);
}

// 3. Sole candidate with score < SCORE_T → reject.
static void test_sole_below_threshold_reject() {
    const uint64_t E = 0x1000;
    auto train = make_feats({"x"}, {0x10}, 100);
    // No const/imm/size overlap → only 1 vote → score 1.0 < 3.0
    auto tgt = make_feats({"y"}, {0x20}, 1000);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = tgt;

    std::vector<HitVote> votes = {{0x1010, E}};
    auto r = resolve_multi_hit_entry(votes, train, target_feats);
    REQUIRE(!r.has_value());
}

// 4. Size band bonus: size in range adds +2.0, pushing score over SCORE_T.
static void test_size_band_bonus() {
    const uint64_t E = 0x1000;
    // Train has no consts/imms, so only vote + size contribute.
    auto train = make_feats({}, {}, 100);
    // Target size 150 is in [50, 300] → +2.0
    auto tgt = make_feats({}, {}, 150);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = tgt;

    // 1 vote → vote=1.0; size=2.0 → total=3.0 = SCORE_T → accept.
    std::vector<HitVote> votes = {{0x1010, E}};
    auto r = resolve_multi_hit_entry(votes, train, target_feats);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E);
    REQUIRE(r->score == 3.0f);

    // Without size bonus (out of band), score would be 1.0 < 3.0 → reject.
    auto tgt_oob = make_feats({}, {}, 1000);
    std::unordered_map<uint64_t, mp::FunctionFeatures> feats_oob;
    feats_oob[E] = tgt_oob;
    auto r2 = resolve_multi_hit_entry(votes, train, feats_oob);
    REQUIRE(!r2.has_value());
}

// Extra: no target feature record → vote-only score used (backward compat).
static void test_no_features_vote_only() {
    const uint64_t E = 0x1000;
    auto train = make_feats({"a"}, {0x10}, 100);
    // No target_feats entry for E → only vote component.
    std::unordered_map<uint64_t, mp::FunctionFeatures> empty_feats;
    std::vector<HitVote> votes = {
        {0x1010, E}, {0x1020, E}, {0x1030, E},
    };
    auto r = resolve_multi_hit_entry(votes, train, empty_feats);
    REQUIRE(r.has_value());
    REQUIRE(r->score == 3.0f); // 3 votes, no features
}

// Extra: stable imm filter — large imm excluded from feature set.
static void test_stable_imm_filter() {
    REQUIRE(mp::is_stable_imm(0x10) == true);
    REQUIRE(mp::is_stable_imm(0x100) == true);   // < 0x10000
    REQUIRE(mp::is_stable_imm(0xFFFF) == true);  // < 0x10000
    REQUIRE(mp::is_stable_imm(0x10000) == false); // not < 0x10000
    REQUIRE(mp::is_stable_imm(0x20) == true);
    REQUIRE(mp::is_stable_imm(0x100000) == false); // large, not in known set
    REQUIRE(mp::is_stable_imm(-0x10) == true);  // abs < 0x10000
}

int main(int argc, char **argv) {
    std::string sel = (argc > 1) ? argv[1] : "all";
    if (sel == "all" || sel == "vote") test_vote_component();
    if (sel == "all" || sel == "const") test_const_component();
    if (sel == "all" || sel == "imm") test_imm_component();
    if (sel == "all" || sel == "size") test_size_component();
    if (sel == "all" || sel == "twin-identical") test_twin_identical_reject();
    if (sel == "all" || sel == "twin-distinct") test_twin_distinct_strings_accept();
    if (sel == "all" || sel == "sole-below") test_sole_below_threshold_reject();
    if (sel == "all" || sel == "size-band") test_size_band_bonus();
    if (sel == "all" || sel == "vote-only") test_no_features_vote_only();
    if (sel == "all" || sel == "imm-filter") test_stable_imm_filter();
    std::puts("test_soft_score: ok");
    return 0;
}
