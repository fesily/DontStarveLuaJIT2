// Micro-window pattern generator and multi-hit same-entry resolver
// (plan function-relocation-match-v2, todo 2).
//
// Header-only: depends only on MatchPolicy.hpp + the C++23 standard library,
// so the unit test builds standalone (no frida-gum, no function_relocation link).
// The production caller in Signature.cpp decodes a function body with capstone,
// classifies each instruction into a MicroInsn (reusing the existing wildcard
// rules but WITHOUT embedding callee prologues), and calls the generator below.
//
// Window model:
//   * Split the instruction stream at X86_INS_CALL and unconditional X86_INS_JMP
//     only (conditional branches are NOT separators — they stay in windows).
//   * The splitting instruction itself is dropped: windows may end immediately
//     before a call/jmp and start immediately after it, but never contain it.
//   * Within each contiguous segment, slide windows of insn length [5,16] by one
//     instruction. Skip any window whose hex pattern has fewer than 5 non-wildcard
//     distinguishing bytes.
//   * Order windows by descending weight (prefer higher calcBlockScore regions).
//
// Multi-hit same-entry resolution:
//   * Accumulate (raw_match, entry) votes across all windows for one function.
//   * Bucket by entry; score each candidate = min(vote_count, W_VOTE_CAP) *
//     W_VOTE_PER_WINDOW into both compact and flat channels (features deferred to
//     todo 3).
//   * Run accept_candidates. Multi-entry without a SCORE_M margin FAILS-CLOSED.
//   * Return entry VA; pattern_offset = entry - earliest raw match for the winner.

#pragma once

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "MatchPolicy.hpp"

namespace function_relocation::micro_window {

// One decoded instruction, pre-classified for the generator. The production
// caller fills this from a capstone cs_insn; tests construct them by hand.
struct MicroInsn {
    uint64_t address = 0;    // VA of the instruction
    size_t size = 0;         // byte length
    bool splits = false;     // true for CALL and unconditional JMP — ends a segment
    std::string hex;         // pre-wildcarded hex pattern ("xx " per byte; "?? " wildcard)
    float weight = 0.0f;     // block score of the containing CodeBlock
};

// One generated micro-window pattern.
struct MicroWindow {
    std::string pattern;            // concatenated hex of the window's instructions
    int train_signature_offset = 0; // entry - window_start_address (training offset)
    float weight = 0.0f;            // max block score among window insns (sort key)
};

// A single (raw_match, entry) vote from one window's target scan.
struct HitVote {
    uintptr_t raw_match = 0;
    uint64_t entry = 0;
};

// Count non-wildcard distinguishing bytes in a hex pattern string. Tokens are
// two hex digits or "??", separated by spaces. A token counts when both chars
// are hex digits. Returns the number of fixed (distinguishing) bytes.
inline int count_distinguishing_bytes(std::string_view pattern) {
    int count = 0;
    size_t i = 0;
    const size_t n = pattern.size();
    while (i < n) {
        while (i < n && pattern[i] == ' ') ++i;
        if (i + 1 >= n) break;
        char a = pattern[i];
        char b = pattern[i + 1];
        auto is_hex = [](char c) {
            return std::isxdigit(static_cast<unsigned char>(c)) != 0;
        };
        if (a != '?' && b != '?' && is_hex(a) && is_hex(b)) {
            ++count;
        }
        i += 2;
        while (i < n && pattern[i] != ' ') ++i;
    }
    return count;
}

// Generate all micro-windows from a decoded instruction stream. `entry_address`
// is the function entry VA used to compute train_signature_offset for each
// window. Returns windows sorted by descending weight (highest score first).
inline std::vector<MicroWindow> generate_micro_windows(
        std::span<const MicroInsn> insns, uint64_t entry_address) {
    std::vector<MicroWindow> out;
    const size_t total = insns.size();
    size_t i = 0;
    while (i < total) {
        // Skip splitting instructions — they cannot start a segment.
        while (i < total && insns[i].splits) ++i;
        const size_t seg_start = i;
        while (i < total && !insns[i].splits) ++i;
        const size_t seg_end = i; // exclusive
        const size_t seg_len = seg_end - seg_start;
        if (seg_len < 5) continue; // minimum window length is 5 insns

        for (size_t wlen = 5; wlen <= 16 && wlen <= seg_len; ++wlen) {
            for (size_t wstart = seg_start; wstart + wlen <= seg_end; ++wstart) {
                std::string pattern;
                float weight = 0.0f;
                for (size_t k = wstart; k < wstart + wlen; ++k) {
                    pattern += insns[k].hex;
                    if (insns[k].weight > weight) weight = insns[k].weight;
                }
                // Trim trailing whitespace.
                while (!pattern.empty() && pattern.back() == ' ') pattern.pop_back();
                if (count_distinguishing_bytes(pattern) < 5) continue;

                const uint64_t win_addr = insns[wstart].address;
                const int train_off = static_cast<int>(
                        static_cast<intptr_t>(entry_address) -
                        static_cast<intptr_t>(win_addr));
                out.push_back({pattern, train_off, weight});
            }
        }
    }
    std::sort(out.begin(), out.end(),
              [](const MicroWindow &a, const MicroWindow &b) {
                  return a.weight > b.weight;
              });
    return out;
}

// Resolve accumulated multi-hit votes to a single entry via accept_candidates.
// vote score = min(count, W_VOTE_CAP) * W_VOTE_PER_WINDOW, applied to both
// compact and flat channels. Returns nullopt on fail-closed (ambiguous entries
// without margin, or winning score below SCORE_T).
inline std::optional<match_policy::AcceptResult>
resolve_multi_hit_entry(std::vector<HitVote> votes) {
    using match_policy::AcceptResult;
    using match_policy::MatchCandidate;
    using match_policy::W_VOTE_CAP;
    using match_policy::W_VOTE_PER_WINDOW;

    if (votes.empty()) return std::nullopt;

    std::unordered_map<uint64_t, MatchCandidate> by_entry;
    for (auto &v : votes) {
        auto &c = by_entry[v.entry];
        c.entry = v.entry;
        c.raw_matches.push_back(v.raw_match);
    }

    std::vector<MatchCandidate> candidates;
    candidates.reserve(by_entry.size());
    for (auto &[e, c] : by_entry) {
        const float vote = std::min(static_cast<float>(c.raw_matches.size()),
                                    W_VOTE_CAP);
        const float score = vote * W_VOTE_PER_WINDOW;
        c.score_compact = score;
        c.score_flat = score;
        candidates.push_back(std::move(c));
    }
    return match_policy::accept_candidates(std::move(candidates));
}

// Resolve accumulated multi-hit votes with feature scoring (plan todo 3).
// train_features: features extracted from the original (training) function.
// target_features: per-entry features for each candidate target entry. If an
//   entry has no feature record, only the vote component is used for it.
//
// Per candidate entry:
//   score = vote_component(distinct_window_hits)
//         + const_component(train.consts, target.consts)
//         + imm_component(train.imms, target.imms)
//         + size_component(train.size, target.size)
// Applied to BOTH compact and flat channels (flatten1 deferred to todo 4, so
// both channels use the same train features — they agree by construction until
// todo 4 introduces distinct flat features).
inline std::optional<match_policy::AcceptResult>
resolve_multi_hit_entry(
        std::vector<HitVote> votes,
        const match_policy::FunctionFeatures &train_features,
        const std::unordered_map<uint64_t, match_policy::FunctionFeatures> &target_features) {
    using match_policy::AcceptResult;
    using match_policy::MatchCandidate;
    namespace mp = match_policy;

    if (votes.empty()) return std::nullopt;

    std::unordered_map<uint64_t, MatchCandidate> by_entry;
    for (auto &v : votes) {
        auto &c = by_entry[v.entry];
        c.entry = v.entry;
        c.raw_matches.push_back(v.raw_match);
    }

    std::vector<MatchCandidate> candidates;
    candidates.reserve(by_entry.size());
    for (auto &[e, c] : by_entry) {
        const float vote = mp::vote_component(c.raw_matches.size());
        float feat = vote;
        auto it = target_features.find(e);
        if (it != target_features.end()) {
            feat += mp::const_component(train_features.consts, it->second.consts);
            feat += mp::imm_component(train_features.imms, it->second.imms);
            feat += mp::size_component(train_features.size, it->second.size);
        }
        c.score_compact = feat;
        c.score_flat = feat;
        candidates.push_back(std::move(c));
    }
    return mp::accept_candidates(std::move(candidates));
}

// Build feature-scored MatchCandidate records from votes + features (plan todo 4
// scoring). Exposed so the production caller (Signature.cpp) can log best/second
// scores and entries on fail-closed before calling accept_candidates, and so
// limit_signature can re-validate shortened patterns against the SAME accept
// policy without re-extracting features.
//
//   train_own:   compact-channel train features (the original function only).
//   train_flat:  flat-channel train features (flatten1 = own ∪ helpers).
//   helper_edges: features of each eligible direct train helper callee.
//   target_features:        per-entry own features for each candidate.
//   target_call_callees:    per-entry list of callee features for the entry's
//                           direct call edges (for StillCall fingerprinting).
//
// Per candidate entry E:
//   call_edit = call_edit_total(helper_edges,
//                               target_call_callees[E],
//                               target_features[E])      (same both channels)
//   score_compact = vote + const(train_own.consts, E.consts)
//                        + imm(train_own.imms, E.imms)
//                        + size(train_own.size, E.size)
//                        + call_edit
//   score_flat    = vote + const(train_flat.consts, E.consts)
//                        + imm(train_flat.imms, E.imms)
//                        + size(train_own.size, E.size)
//                        + call_edit
// accept_candidates (called separately) enforces the agree rule, SCORE_M
// margin, and SCORE_T.
inline std::vector<match_policy::MatchCandidate> build_feature_candidates(
        const std::vector<HitVote> &votes,
        const match_policy::FunctionFeatures &train_own,
        const match_policy::FunctionFeatures &train_flat,
        const std::vector<match_policy::FunctionFeatures> &helper_edges,
        const std::unordered_map<uint64_t, match_policy::FunctionFeatures> &target_features,
        const std::unordered_map<uint64_t, std::vector<match_policy::FunctionFeatures>> &target_call_callees) {
    using match_policy::MatchCandidate;
    namespace mp = match_policy;

    std::unordered_map<uint64_t, MatchCandidate> by_entry;
    for (const auto &v : votes) {
        auto &c = by_entry[v.entry];
        c.entry = v.entry;
        c.raw_matches.push_back(v.raw_match);
    }

    std::vector<MatchCandidate> candidates;
    candidates.reserve(by_entry.size());
    for (auto &[e, c] : by_entry) {
        const float vote = mp::vote_component(c.raw_matches.size());
        auto tf_it = target_features.find(e);
        const match_policy::FunctionFeatures &tf =
                (tf_it != target_features.end()) ? tf_it->second : match_policy::FunctionFeatures{};

        auto tc_it = target_call_callees.find(e);
        const std::vector<match_policy::FunctionFeatures> &tc =
                (tc_it != target_call_callees.end()) ? tc_it->second
                                                      : std::vector<match_policy::FunctionFeatures>{};

        const float call_edit = mp::call_edit_total(helper_edges, tc, tf);

        float compact = vote;
        if (tf_it != target_features.end()) {
            compact += mp::const_component(train_own.consts, tf.consts);
            compact += mp::imm_component(train_own.imms, tf.imms);
            compact += mp::size_component(train_own.size, tf.size);
        }
        c.score_compact = compact + call_edit;

        float flat = vote;
        if (tf_it != target_features.end()) {
            flat += mp::const_component(train_flat.consts, tf.consts);
            flat += mp::imm_component(train_flat.imms, tf.imms);
            flat += mp::size_component(train_own.size, tf.size);
        }
        c.score_flat = flat + call_edit;

        candidates.push_back(std::move(c));
    }
    return candidates;
}

// Resolve accumulated multi-hit votes with dual-channel feature scoring and
// call-edit labels (plan todo 4). Replaces the T3 single-feature overload in
// the production path. Builds candidates via build_feature_candidates and then
// enforces the agree rule, SCORE_M margin, and SCORE_T via accept_candidates.
inline std::optional<match_policy::AcceptResult>
resolve_multi_hit_entry(
        std::vector<HitVote> votes,
        const match_policy::FunctionFeatures &train_own,
        const match_policy::FunctionFeatures &train_flat,
        const std::vector<match_policy::FunctionFeatures> &helper_edges,
        const std::unordered_map<uint64_t, match_policy::FunctionFeatures> &target_features,
        const std::unordered_map<uint64_t, std::vector<match_policy::FunctionFeatures>> &target_call_callees) {
    using match_policy::AcceptResult;
    if (votes.empty()) return std::nullopt;
    auto candidates = build_feature_candidates(votes, train_own, train_flat,
                                               helper_edges, target_features,
                                               target_call_callees);
    return match_policy::accept_candidates(std::move(candidates));
}

// Summarize candidate scores for fail-closed logging (plan todo 5). Pure helper
// so Signature.cpp can log best/second/entries via spdlog and unit tests can
// exercise the sort+margin arithmetic without linking frida-gum. Returns a
// compact one-line string: "n=N best=E score=S second=E score=S margin=M" (the
// second/second score/margin are omitted when fewer than 2 candidates).
struct CandidateSummary {
    size_t count = 0;
    uint64_t best_entry = 0;
    float best_score = 0.0f;
    uint64_t second_entry = 0;
    float second_score = 0.0f;
    float margin = 0.0f;
    bool has_second = false;
};
inline CandidateSummary summarize_candidates(
        const std::vector<match_policy::MatchCandidate> &candidates) {
    CandidateSummary s;
    s.count = candidates.size();
    if (candidates.empty()) return s;
    std::vector<std::pair<float, uint64_t>> scored;
    scored.reserve(candidates.size());
    for (const auto &c : candidates) {
        scored.emplace_back(std::max(c.score_compact, c.score_flat), c.entry);
    }
    std::sort(scored.begin(), scored.end(),
              [](const auto &a, const auto &b) { return a.first > b.first; });
    s.best_score = scored[0].first;
    s.best_entry = scored[0].second;
    if (scored.size() >= 2) {
        s.has_second = true;
        s.second_score = scored[1].first;
        s.second_entry = scored[1].second;
        s.margin = s.best_score - s.second_score;
    }
    return s;
}

} // namespace function_relocation::micro_window
