// Unit tests for the soft-match accept policy primitives (plan
// function-relocation-match-v2, todo 1). Exercises accept_candidates in
// isolation; no frida-gum, no function_relocation link required.

#include "MatchPolicy.hpp"

#include <cstdio>
#include <cstdlib>

using namespace function_relocation::match_policy;

#define REQUIRE(cond)                                                                          \
  do {                                                                                         \
    if (!(cond)) {                                                                             \
      std::fprintf(stderr, "REQUIRE failed: %s (%s:%d)\n", #cond, __FILE__, __LINE__);        \
      std::abort();                                                                            \
    }                                                                                          \
  } while (0)

static MatchCandidate make_candidate(uint64_t entry, std::vector<uintptr_t> matches,
                                      float score_compact, float score_flat) {
    MatchCandidate c;
    c.entry = entry;
    c.raw_matches = std::move(matches);
    c.score_compact = score_compact;
    c.score_flat = score_flat;
    return c;
}

// Happy: sole entry score 4.0 -> accept.
static void test_accept_sole() {
    auto r = accept_candidates({make_candidate(0x1000, {0x1000}, 4.0f, 4.0f)});
    REQUIRE(r.has_value());
    REQUIRE(r->entry == 0x1000);
    REQUIRE(r->score == 4.0f);
    REQUIRE(r->chosen_raw_match == 0x1000);
}

// Failure: twin scores 5.0 / 4.0 gap 1.0 < SCORE_M(1.5) -> reject.
static void test_reject_twin_small_gap() {
    auto r = accept_candidates({
        make_candidate(0x1000, {0x1000}, 5.0f, 5.0f),
        make_candidate(0x2000, {0x2000}, 4.0f, 4.0f),
    });
    REQUIRE(!r.has_value());
}

// Happy: gap 2.0 >= SCORE_M -> accept best.
static void test_accept_gap_two() {
    auto r = accept_candidates({
        make_candidate(0x1000, {0x1000}, 5.0f, 5.0f),
        make_candidate(0x2000, {0x2000}, 3.0f, 3.0f),
    });
    REQUIRE(r.has_value());
    REQUIRE(r->entry == 0x1000);
    REQUIRE(r->score == 5.0f);
}

// Failure: score 2.9 < SCORE_T(3.0) -> reject even as sole candidate.
static void test_reject_below_threshold() {
    auto r = accept_candidates({make_candidate(0x1000, {0x1000}, 2.9f, 2.9f)});
    REQUIRE(!r.has_value());
}

// Failure: compact best entry != flat best entry -> fail-closed.
static void test_reject_compact_flat_disagree() {
    auto r = accept_candidates({
        make_candidate(0x1000, {0x1000}, 5.0f, 0.0f),
        make_candidate(0x2000, {0x2000}, 0.0f, 4.0f),
    });
    REQUIRE(!r.has_value());
}

// Extra coverage: chosen_raw_match is the earliest raw match for the winner.
static void test_earliest_raw_match() {
    auto r = accept_candidates({
        make_candidate(0x1000, {0x1010, 0x1000, 0x1008}, 4.0f, 4.0f),
    });
    REQUIRE(r.has_value());
    REQUIRE(r->entry == 0x1000);
    REQUIRE(r->chosen_raw_match == 0x1000);
}

// Extra coverage: empty candidate list -> reject.
static void test_reject_empty() {
    auto r = accept_candidates({});
    REQUIRE(!r.has_value());
}

// Extra coverage: both channels zero -> no positive signal -> reject.
static void test_reject_no_positive_signal() {
    auto r = accept_candidates({make_candidate(0x1000, {0x1000}, 0.0f, 0.0f)});
    REQUIRE(!r.has_value());
}

int main() {
    test_accept_sole();
    test_reject_twin_small_gap();
    test_accept_gap_two();
    test_reject_below_threshold();
    test_reject_compact_flat_disagree();
    test_earliest_raw_match();
    test_reject_empty();
    test_reject_no_positive_signal();
    std::puts("test_match_accept_policy: ok");
    return 0;
}
