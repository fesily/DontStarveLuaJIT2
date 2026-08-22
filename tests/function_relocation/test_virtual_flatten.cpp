// Unit tests for virtual flatten1 + call-edit StillCall|Inlined|Missing and
// dual-channel compact/flat agree (plan function-relocation-match-v2, todo 4).
// Header-only: depends on MatchPolicy.hpp + MicroWindow.hpp + the C++23 stdlib.
//
// Scenarios:
//   1. inline: parent train has call helper; target has helper body inlined
//      (no call) -> Inlined label contributes +0.8; accept parent.
//   2. disagree: compact best entry != flat best entry -> reject (FAIL-CLOSED).
//   3. StillCall: target still has call to matching callee -> +1.0.
//   4. Missing: no call, no coverage -> -0.5.

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

// --- Pure call-edit label tests ---

// 3. StillCall: target callee fingerprint-matches helper -> +W_CALL_STILL.
static void test_stillcall_label() {
    auto helper = make_feats({"helper_str"}, {0x10}, 50);
    auto callee = make_feats({"helper_str", "extra"}, {0x10}, 50);
    auto entry  = make_feats({"parent"}, {}, 100);

    std::vector<mp::FunctionFeatures> callees = {callee};
    REQUIRE(mp::label_call_edge(helper, callees, entry) == mp::CallEdit::StillCall);
    REQUIRE(mp::call_edit_component(helper, callees, entry) == mp::W_CALL_STILL);
    REQUIRE(mp::call_edit_component(helper, callees, entry) == 1.0f);
}

// 4. Missing: no matching call, no coverage -> -W_CALL_MISSING.
static void test_missing_label() {
    auto helper = make_feats({"helper_str"}, {0x10}, 50);
    auto entry  = make_feats({"unrelated"}, {0x99}, 100);

    std::vector<mp::FunctionFeatures> callees;
    REQUIRE(mp::label_call_edge(helper, callees, entry) == mp::CallEdit::Missing);
    REQUIRE(mp::call_edit_component(helper, callees, entry) == mp::W_CALL_MISSING);
    REQUIRE(mp::call_edit_component(helper, callees, entry) == -0.5f);
}

// Inlined pure label: no call, but target covers >=50% of helper features.
static void test_inlined_label_pure() {
    auto helper = make_feats({"a", "b"}, {0x10}, 50);
    auto entry  = make_feats({"a", "b", "c"}, {0x10}, 100); // 3 of 3 helper features

    std::vector<mp::FunctionFeatures> callees;
    REQUIRE(mp::label_call_edge(helper, callees, entry) == mp::CallEdit::Inlined);
    REQUIRE(mp::call_edit_component(helper, callees, entry) == mp::W_CALL_INLINED);
    REQUIRE(mp::call_edit_component(helper, callees, entry) == 0.8f);
}

// flatten1_features: union of own + helpers, size stays own.
static void test_flatten1_features() {
    auto own = make_feats({"own_str"}, {0x10}, 100);
    auto h1  = make_feats({"helper1"}, {0x20}, 50);
    auto h2  = make_feats({"helper2"}, {0x30}, 30);

    auto flat = mp::flatten1_features(own, {h1, h2});
    REQUIRE(flat.size == 100); // size unchanged
    REQUIRE(flat.consts.size() == 3);
    REQUIRE(flat.imms.size() == 3);
}

// --- Dual-channel resolve integration tests ---

// 1. Inline case: parent train has call helper; target has helper body inlined
//    (no call). Inlined contributes +0.8; accept parent when features match.
static void test_inline_accept() {
    const uint64_t E = 0x1000;

    // Train own features: parent only.
    auto train_own = make_feats({"parent"}, {0x10}, 100);
    // Helper edge: the function the parent calls.
    auto helper = make_feats({"helper_str"}, {0x20}, 50);
    // Flat = own + helper features.
    auto train_flat = mp::flatten1_features(train_own, {helper});

    // Target entry: has parent + inlined helper features, no call to helper.
    auto tgt = make_feats({"parent", "helper_str"}, {0x10, 0x20}, 150);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = tgt;
    // No call callees (helper was inlined, not called).
    std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> target_callees;

    std::vector<mp::FunctionFeatures> helper_edges = {helper};

    // Enough votes to pass threshold.
    std::vector<HitVote> votes = {
        {0x1010, E}, {0x1020, E}, {0x1030, E}, {0x1040, E},
    };

    auto r = resolve_multi_hit_entry(votes, train_own, train_flat,
                                     helper_edges, target_feats, target_callees);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E);

    // Compact score: vote(4) + const(parent vs parent+helper: 1/1 * 10 = 10)
    //   + imm(0x10 in {0x10,0x20}: 1/1 * 4 = 4) + size(100 vs 150 in [50,300]: 2)
    //   + call_edit(Inlined: 0.8) = 4 + 10 + 4 + 2 + 0.8 = 20.8
    // Flat score: vote(4) + const(parent+helper vs parent+helper: 1/1 * 10 = 10)
    //   + imm(0x10,0x20 vs 0x10,0x20: 1/1 * 4 = 4) + size(100 vs 150: 2)
    //   + call_edit(0.8) = 20.8
    // Both agree on E, score = max = 20.8.
    REQUIRE(r->score == 20.8f);
}

// 2. Disagree: compact best entry != flat best entry -> FAIL-CLOSED.
static void test_disagree_reject() {
    const uint64_t E1 = 0x1000; // matches compact (own features)
    const uint64_t E2 = 0x2000; // matches flat (flattened features)

    auto train_own = make_feats({"own"}, {0x10}, 100);
    // Helper edge adds "helper" string, only in flat features.
    auto helper = make_feats({"helper"}, {0x20}, 50);
    auto train_flat = mp::flatten1_features(train_own, {helper});

    // E1 matches own features (has "own"), not flat-exclusive features.
    auto tgt1 = make_feats({"own"}, {0x10}, 100);
    // E2 matches flat-exclusive features (has "helper"), not own features.
    auto tgt2 = make_feats({"helper"}, {0x20}, 100);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E1] = tgt1;
    target_feats[E2] = tgt2;

    // No call callees (simplify the disagree to be about features, not calls).
    std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> target_callees;
    std::vector<mp::FunctionFeatures> helper_edges = {helper};

    // Equal votes for both entries.
    std::vector<HitVote> votes = {
        {0x1010, E1}, {0x1020, E1}, {0x1030, E1}, {0x1040, E1},
        {0x2010, E2}, {0x2020, E2}, {0x2030, E2}, {0x2040, E2},
    };

    auto r = resolve_multi_hit_entry(votes, train_own, train_flat,
                                     helper_edges, target_feats, target_callees);
    // compact: E1 score = 4(vote) + 10(const: own vs own) + 4(imm) + 2(size) + call_edit
    //   call_edit for E1: helper has "helper"+0x20; E1 has "own"+0x10 -> Missing (-0.5)
    //   compact E1 = 4 + 10 + 4 + 2 - 0.5 = 19.5
    //   compact E2 = 4 + 0(const: own vs helper) + 0(imm: 0x10 vs 0x20) + 2(size) + call_edit
    //   call_edit for E2: helper has "helper"+0x20; E2 has "helper"+0x20 -> coverage=1.0 -> Inlined (0.8)
    //   compact E2 = 4 + 0 + 0 + 2 + 0.8 = 6.8
    //   compact best = E1 (19.5)
    // flat: E1 score = 4 + const(flat={own,helper} vs {own}: 1/2 * 10 = 5) + imm(flat={0x10,0x20} vs {0x10}: 1/2*4=2)
    //   + size(2) + call_edit(Missing -0.5) = 4 + 5 + 2 + 2 - 0.5 = 12.5
    //   flat E2 = 4 + const(flat vs {helper}: 1/2*10=5) + imm(flat vs {0x20}: 1/2*4=2) + size(2)
    //   + call_edit(Inlined 0.8) = 4 + 5 + 2 + 2 + 0.8 = 13.8
    //   flat best = E2 (13.8)
    // compact best E1 != flat best E2 -> FAIL-CLOSED
    REQUIRE(!r.has_value());
}

// StillCall integration: target has a call whose callee matches helper fingerprint.
static void test_stillcall_accept() {
    const uint64_t E = 0x1000;

    auto train_own = make_feats({"parent"}, {0x10}, 100);
    auto helper = make_feats({"helper_str"}, {0x20}, 50);
    auto train_flat = mp::flatten1_features(train_own, {helper});

    // Target entry has parent features.
    auto tgt = make_feats({"parent"}, {0x10}, 100);
    // Target callee (the function the target calls) matches helper fingerprint.
    auto callee = make_feats({"helper_str", "extra"}, {0x20}, 50);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = tgt;
    std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> target_callees;
    target_callees[E] = {callee};

    std::vector<mp::FunctionFeatures> helper_edges = {helper};

    std::vector<HitVote> votes = {
        {0x1010, E}, {0x1020, E}, {0x1030, E}, {0x1040, E},
    };

    auto r = resolve_multi_hit_entry(votes, train_own, train_flat,
                                     helper_edges, target_feats, target_callees);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E);
    // compact: vote(4) + const(parent vs parent: 10) + imm(0x10: 4) + size(2)
    //   + call_edit(StillCall: 1.0) = 4 + 10 + 4 + 2 + 1.0 = 21.0
    REQUIRE(r->score == 21.0f);
}

// Missing integration: no call, no coverage -> -0.5 contribution.
static void test_missing_contribute() {
    const uint64_t E = 0x1000;

    auto train_own = make_feats({"parent"}, {0x10}, 100);
    auto helper = make_feats({"helper_str"}, {0x20}, 50);
    auto train_flat = mp::flatten1_features(train_own, {helper});

    // Target has no helper features and no matching callee.
    auto tgt = make_feats({"parent"}, {0x10}, 100);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = tgt;
    std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> target_callees;

    std::vector<mp::FunctionFeatures> helper_edges = {helper};

    std::vector<HitVote> votes = {
        {0x1010, E}, {0x1020, E}, {0x1030, E}, {0x1040, E},
    };

    auto r = resolve_multi_hit_entry(votes, train_own, train_flat,
                                     helper_edges, target_feats, target_callees);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E);
    // compact: vote(4) + const(parent vs parent: 10) + imm(0x10: 4) + size(2)
    //   + call_edit(Missing: -0.5) = 4 + 10 + 4 + 2 - 0.5 = 19.5
    REQUIRE(r->score == 19.5f);
}

// No helper edges: degrades to T3 behavior (compact == flat).
static void test_no_helpers_degrades() {
    const uint64_t E = 0x1000;
    auto train = make_feats({"a"}, {0x10}, 100);
    auto tgt = make_feats({"a"}, {0x10}, 100);

    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = tgt;
    std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> target_callees;
    std::vector<mp::FunctionFeatures> helper_edges;

    std::vector<HitVote> votes = {
        {0x1010, E}, {0x1020, E}, {0x1030, E},
    };
    auto r = resolve_multi_hit_entry(votes, train, train, helper_edges,
                                     target_feats, target_callees);
    REQUIRE(r.has_value());
    REQUIRE(r->entry == E);
    // vote(3) + const(10) + imm(4) + size(2) = 19.0
    REQUIRE(r->score == 19.0f);
}

int main(int argc, char **argv) {
    std::string sel = (argc > 1) ? argv[1] : "all";
    if (sel == "all" || sel == "stillcall-label") test_stillcall_label();
    if (sel == "all" || sel == "missing-label") test_missing_label();
    if (sel == "all" || sel == "inlined-label") test_inlined_label_pure();
    if (sel == "all" || sel == "flatten1") test_flatten1_features();
    if (sel == "all" || sel == "inline-accept") test_inline_accept();
    if (sel == "all" || sel == "disagree") test_disagree_reject();
    if (sel == "all" || sel == "stillcall-accept") test_stillcall_accept();
    if (sel == "all" || sel == "missing-contribute") test_missing_contribute();
    if (sel == "all" || sel == "no-helpers") test_no_helpers_degrades();
    std::puts("test_virtual_flatten: ok");
    return 0;
}
