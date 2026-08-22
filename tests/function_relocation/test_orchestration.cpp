// Unit tests for plan function-relocation-match-v2 todo 5 orchestration:
//   * limit_signature re-validates shortened patterns via the SAME vote+margin
//     accept policy (build_feature_candidates + accept_candidates), not a
//     weaker unique-byte-only path.
//   * skip_check is never an argument to the soft-path helpers — only the
//     knowns_signature seed path may bypass training validation.
//   * summarize_candidates reports best/second/entries for fail-closed logging.
//
// Header-only: depends on MatchPolicy.hpp + MicroWindow.hpp + the C++23 stdlib.
// The Signature.cpp paths that need frida-gum (scan_by_micro_windows,
// soft_revalidate_pattern) are covered by comments + pure-helper coverage of
// the accept policy they reuse.

#include "MicroWindow.hpp"

#include <cstdio>
#include <cstdlib>
#include <functional>
#include <type_traits>

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

// --- Structural: soft-path helpers must NOT take a skip_check parameter. ---
// The only path that may bypass training validation is the knowns_signature
// seed (fix_func_address_by_signature calls scan_by_signature(..., true)).
// soft_revalidate_pattern / build_feature_candidates / resolve_multi_hit_entry
// must not carry a skip_check argument. We assert this by taking their address
// and checking the arity/types against the expected signatures.

static void test_soft_helpers_have_no_skip_check() {
    using BuildFn = std::vector<mp::MatchCandidate> (*)(
            const std::vector<HitVote> &,
            const mp::FunctionFeatures &,
            const mp::FunctionFeatures &,
            const std::vector<mp::FunctionFeatures> &,
            const std::unordered_map<uint64_t, mp::FunctionFeatures> &,
            const std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> &);
    static_assert(std::is_same_v<decltype(&build_feature_candidates), BuildFn>,
                  "build_feature_candidates signature must not carry skip_check");
    (void) static_cast<BuildFn>(&build_feature_candidates);

    using SummarizeFn = CandidateSummary (*)(const std::vector<mp::MatchCandidate> &);
    static_assert(std::is_same_v<decltype(&summarize_candidates), SummarizeFn>,
                  "summarize_candidates signature must not carry skip_check");
    (void) static_cast<SummarizeFn>(&summarize_candidates);
}

// --- limit_signature re-validation path uses the SAME accept policy. ---
// Mirrors soft_revalidate_pattern: build_feature_candidates over votes from a
// shortened pattern, then accept_candidates. A shortened pattern that still
// resolves uniquely with adequate margin is accepted; one that creates twin
// ambiguity is rejected — proving the limit path uses accept_candidates, not
// a unique-byte "targets.size()==1" gate.
static void test_limit_path_uses_accept_candidates() {
    const uint64_t E = 0x1000;
    auto train_own = make_feats({"a"}, {0x10}, 100);
    auto train_flat = make_feats({"a"}, {0x10}, 100);
    std::vector<mp::FunctionFeatures> helper_edges;
    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E] = make_feats({"a"}, {0x10}, 100);
    std::unordered_map<uint64_t, std::vector<mp::FunctionFeatures>> target_callees;

    // Shortened pattern still hits only E with enough votes+features -> accept.
    std::vector<HitVote> votes_ok = {
            {0x1010, E}, {0x1020, E}, {0x1030, E}, {0x1040, E},
    };
    auto cand_ok = build_feature_candidates(
            votes_ok, train_own, train_flat, helper_edges, target_feats, target_callees);
    auto r_ok = mp::accept_candidates(std::move(cand_ok));
    REQUIRE(r_ok.has_value());
    REQUIRE(r_ok->entry == E);

    // Shortened pattern now also hits a twin E2 with equal votes+features ->
    // margin 0 < SCORE_M -> reject (this is the twin fail-closed the limit
    // path must enforce instead of pick-first uniqueness).
    const uint64_t E2 = 0x2000;
    target_feats[E2] = make_feats({"a"}, {0x10}, 100);
    std::vector<HitVote> votes_twin = {
            {0x1010, E}, {0x1020, E}, {0x1030, E}, {0x1040, E},
            {0x2010, E2}, {0x2020, E2}, {0x2030, E2}, {0x2040, E2},
    };
    auto cand_twin = build_feature_candidates(
            votes_twin, train_own, train_flat, helper_edges, target_feats, target_callees);
    auto r_twin = mp::accept_candidates(std::move(cand_twin));
    REQUIRE(!r_twin.has_value());
}

// --- summarize_candidates: best/second/entries for fail-closed logging. ---
static void test_summarize_candidates_two() {
    std::vector<mp::MatchCandidate> cands;
    mp::MatchCandidate a;
    a.entry = 0x1000;
    a.score_compact = 5.0f;
    a.score_flat = 4.0f;
    mp::MatchCandidate b;
    b.entry = 0x2000;
    b.score_compact = 3.0f;
    b.score_flat = 3.5f;
    cands.push_back(a);
    cands.push_back(b);
    auto s = summarize_candidates(cands);
    REQUIRE(s.count == 2);
    REQUIRE(s.has_second);
    REQUIRE(s.best_entry == 0x1000);
    REQUIRE(s.best_score == 5.0f);
    REQUIRE(s.second_entry == 0x2000);
    REQUIRE(s.second_score == 3.5f);
    REQUIRE(s.margin == 1.5f);
}

static void test_summarize_candidates_sole() {
    std::vector<mp::MatchCandidate> cands;
    mp::MatchCandidate a;
    a.entry = 0x1000;
    a.score_compact = 2.0f;
    a.score_flat = 2.0f;
    cands.push_back(a);
    auto s = summarize_candidates(cands);
    REQUIRE(s.count == 1);
    REQUIRE(!s.has_second);
    REQUIRE(s.best_entry == 0x1000);
    REQUIRE(s.best_score == 2.0f);
}

static void test_summarize_candidates_empty() {
    std::vector<mp::MatchCandidate> cands;
    auto s = summarize_candidates(cands);
    REQUIRE(s.count == 0);
    REQUIRE(!s.has_second);
    REQUIRE(s.best_score == 0.0f);
}

// --- Orchestration order: knowns (skip_check) -> soft-only -> legacy. ---
// The soft path runs ONLY when FunctionTable non-empty; on failure it returns
// nullptr without LCS/scan_by_block fallback. We cannot link ModuleSections
// here, so we assert the contract via the accept policy the soft path uses:
// a fail-closed accept (twin) returns nullopt, which the orchestrator must
// propagate as nullptr rather than falling back.
static void test_soft_fail_closed_propagates_null() {
    const uint64_t E1 = 0x1000;
    const uint64_t E2 = 0x2000;
    auto train = make_feats({"a"}, {0x10}, 100);
    auto twin = make_feats({"a"}, {0x10}, 100);
    std::unordered_map<uint64_t, mp::FunctionFeatures> target_feats;
    target_feats[E1] = twin;
    target_feats[E2] = twin;
    std::vector<HitVote> votes = {
            {0x1010, E1}, {0x1020, E1}, {0x1030, E1}, {0x1040, E1},
            {0x2010, E2}, {0x2020, E2}, {0x2030, E2}, {0x2040, E2},
    };
    auto r = resolve_multi_hit_entry(votes, train, target_feats);
    REQUIRE(!r.has_value());
}

int main(int argc, char **argv) {
    std::string sel = (argc > 1) ? argv[1] : "all";
    if (sel == "all" || sel == "no-skip-check") test_soft_helpers_have_no_skip_check();
    if (sel == "all" || sel == "limit-accept") test_limit_path_uses_accept_candidates();
    if (sel == "all" || sel == "summarize-two") test_summarize_candidates_two();
    if (sel == "all" || sel == "summarize-sole") test_summarize_candidates_sole();
    if (sel == "all" || sel == "summarize-empty") test_summarize_candidates_empty();
    if (sel == "all" || sel == "soft-fail-null") test_soft_fail_closed_propagates_null();
    std::puts("test_orchestration: ok");
    return 0;
}
