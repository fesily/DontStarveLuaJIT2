#pragma once

// Internal soft-match accept policy primitives for function_relocation.
//
// This header is a private implementation detail of Signature.cpp and is
// intentionally NOT exported on the SignatureInfo wire (no JSON fields are
// added). It is exposed as a standalone header only so that unit tests can
// exercise the accept algorithm in isolation without linking frida-gum or
// the function_relocation static library.
//
// Constants and the accept algorithm are locked by the plan
// `.omo/plans/function-relocation-match-v2.md` (todo 1) and MUST NOT be
// changed without updating the plan.

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace function_relocation::match_policy {

    // ------------------------------------------------------------------
    // Locked accept constants (plan: Verification strategy / Locked accept
    // constants). No implementer free choice.
    // ------------------------------------------------------------------

    // SCORE_T: absolute minimum total score to accept a candidate, even when
    // it is the sole candidate.
    inline constexpr float SCORE_T = 3.0f;

    // SCORE_M: required margin between best and second-best candidate score
    // when at least two candidate entries exist. Best - second < SCORE_M is
    // a twin fail-closed.
    inline constexpr float SCORE_M = 1.5f;

    // ------------------------------------------------------------------
    // Feature score weights (sum -> candidate score per channel).
    // ------------------------------------------------------------------

    // W_VOTE: each distinct micro-window that hits this entry contributes
    // +W_VOTE_PER_WINDOW (cap W_VOTE_CAP).
    inline constexpr float W_VOTE_PER_WINDOW = 1.0f;
    inline constexpr float W_VOTE_CAP = 8.0f;

    // W_CONST: 10.0 * jaccard of train_flat_strings vs target_strings
    // (0 if train set empty - do not invent).
    inline constexpr float W_CONST = 10.0f;

    // W_IMM: 4.0 * jaccard of stable immediates.
    inline constexpr float W_IMM = 4.0f;

    // W_SIZE: +2.0 if target_size in [0.5 * train_size, 3.0 * train_size].
    inline constexpr float W_SIZE = 2.0f;
    inline constexpr float W_SIZE_LOWER = 0.5f;
    inline constexpr float W_SIZE_UPPER = 3.0f;

    // W_CALL: per direct train helper edge label contribution.
    inline constexpr float W_CALL_STILL = 1.0f;
    inline constexpr float W_CALL_INLINED = 0.8f;
    inline constexpr float W_CALL_MISSING = -0.5f;

    // Call-edit Inlined coverage threshold: target feature multiset must cover
    // >= this fraction of helper string/imm features for the Inlined label.
    inline constexpr float W_CALL_INLINED_COVERAGE = 0.5f;

    // ------------------------------------------------------------------
    // Stable-immediate gate. An immediate is "stable" (counts toward W_IMM)
    // if |imm| < W_IMM_SMALL or it appears in the common TValue/type
    // constant set used by the Lua C API / ScanCtx scanning heuristics.
    // ------------------------------------------------------------------
    inline constexpr int64_t W_IMM_SMALL = 0x10000; // |imm| < 0x10000

    inline constexpr std::array<int64_t, 12> W_IMM_KNOWN = {
            0x10, 0x18, 0x20, 0x28, 0x30, 0x38,
            0x40, 0x48, 0x50, 0x58, 0x08, 0x00,
    };

    inline bool is_stable_imm(int64_t imm) {
        if (imm < 0) imm = -imm;
        if (imm < W_IMM_SMALL) return true;
        for (auto v : W_IMM_KNOWN) {
            if (imm == v) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // FunctionFeatures: extracted features from a train or target function.
    // Pure value type so unit tests build them by hand without linking
    // frida-gum or ModuleSections.
    // ------------------------------------------------------------------
    struct FunctionFeatures {
        std::vector<std::string> consts;  // rodata string refs
        std::vector<int64_t> imms;        // stable immediates (pre-filtered)
        uint64_t size = 0;                // Function::size (Nucleus span)
    };

    // ------------------------------------------------------------------
    // Pure score component functions. Each implements the exact formula
    // from the plan's Locked accept constants section. Exposed for unit
    // testing so the test binary does not need frida-gum.
    // ------------------------------------------------------------------

    // W_VOTE: min(distinct_window_hits, W_VOTE_CAP) * W_VOTE_PER_WINDOW.
    inline float vote_component(size_t distinct_window_hits) {
        return std::min(static_cast<float>(distinct_window_hits), W_VOTE_CAP) *
               W_VOTE_PER_WINDOW;
    }

    // W_CONST: 10.0 * |train ∩ target| / max(1, |train|); 0 if train empty.
    // Uses set semantics (deduplicated train cardinality).
    inline float const_component(const std::vector<std::string> &train,
                                 const std::vector<std::string> &target) {
        if (train.empty()) return 0.0f;
        std::set<std::string> train_set(train.begin(), train.end());
        std::set<std::string> target_set(target.begin(), target.end());
        size_t hits = 0;
        for (const auto &s : target_set) {
            if (train_set.count(s)) ++hits;
        }
        return W_CONST * static_cast<float>(hits) /
               static_cast<float>(std::max<size_t>(1, train_set.size()));
    }

    // W_IMM: 4.0 * |train ∩ target| / max(1, |train|); 0 if train empty.
    inline float imm_component(const std::vector<int64_t> &train,
                               const std::vector<int64_t> &target) {
        if (train.empty()) return 0.0f;
        std::set<int64_t> train_set(train.begin(), train.end());
        std::set<int64_t> target_set(target.begin(), target.end());
        size_t hits = 0;
        for (auto v : target_set) {
            if (train_set.count(v)) ++hits;
        }
        return W_IMM * static_cast<float>(hits) /
               static_cast<float>(std::max<size_t>(1, train_set.size()));
    }

    // W_SIZE: +2.0 if target_size ∈ [0.5 * train_size, 3.0 * train_size], else 0.
    inline float size_component(uint64_t train_size, uint64_t target_size) {
        if (train_size == 0) return 0.0f;
        const double lo = W_SIZE_LOWER * static_cast<double>(train_size);
        const double hi = W_SIZE_UPPER * static_cast<double>(train_size);
        const double ts = static_cast<double>(target_size);
        return (ts >= lo && ts <= hi) ? W_SIZE : 0.0f;
    }

    // ------------------------------------------------------------------
    // Virtual flatten1 (one-level) and call-edit labels (plan todo 4).
    //
    // flatten1(F) = own features ∪ features of direct same-module helper
    // callees. Soft only: the union is materialized in a new FunctionFeatures
    // value and NEVER written back to FunctionTable / Function::size.
    // Helper eligibility is enforced by the production caller (Signature.cpp);
    // here flatten1_features is a pure set-union over the provided inputs.
    // ------------------------------------------------------------------

    inline FunctionFeatures flatten1_features(
            const FunctionFeatures &own,
            const std::vector<FunctionFeatures> &helper_features) {
        FunctionFeatures flat = own;
        for (const auto &h : helper_features) {
            for (const auto &s : h.consts) flat.consts.push_back(s);
            for (auto v : h.imms) flat.imms.push_back(v);
        }
        return flat;
    }

    // ------------------------------------------------------------------
    // Call-edit label for one direct train helper edge against a target
    // candidate entry. Score-only: contributes to the candidate's compact
    // and flat channel scores, does not wire a SignatureInfo match.
    //
    // StillCall: the target still has a call whose callee fingerprint matches
    //   the helper (+W_CALL_STILL).
    // Inlined: no matching call, but the target entry's feature multiset
    //   covers >= W_CALL_INLINED_COVERAGE of the helper string/imm features
    //   (+W_CALL_INLINED).
    // Missing: neither (-W_CALL_MISSING).
    // ------------------------------------------------------------------

    enum class CallEdit { StillCall, Inlined, Missing };

    // Fingerprint match: the callee's feature set contains every helper const
    // and stable imm, and the helper has at least one distinguishing feature.
    inline bool fingerprint_match(const FunctionFeatures &helper,
                                  const FunctionFeatures &callee) {
        std::set<std::string> h_consts(helper.consts.begin(), helper.consts.end());
        std::set<std::string> c_consts(callee.consts.begin(), callee.consts.end());
        std::set<int64_t> h_imms(helper.imms.begin(), helper.imms.end());
        std::set<int64_t> c_imms(callee.imms.begin(), callee.imms.end());
        if (h_consts.empty() && h_imms.empty()) return false;
        for (const auto &s : h_consts) {
            if (!c_consts.count(s)) return false;
        }
        for (auto v : h_imms) {
            if (!c_imms.count(v)) return false;
        }
        return true;
    }

    // Fraction of helper string/imm features present in the target entry's
    // feature multiset. Returns 0.0 when the helper has no string/imm features.
    inline float feature_coverage(const FunctionFeatures &helper,
                                  const FunctionFeatures &target) {
        std::set<std::string> t_consts(target.consts.begin(), target.consts.end());
        std::set<int64_t> t_imms(target.imms.begin(), target.imms.end());
        size_t total = 0;
        size_t hits = 0;
        for (const auto &s : helper.consts) {
            ++total;
            if (t_consts.count(s)) ++hits;
        }
        for (auto v : helper.imms) {
            ++total;
            if (t_imms.count(v)) ++hits;
        }
        if (total == 0) return 0.0f;
        return static_cast<float>(hits) / static_cast<float>(total);
    }

    // Label one helper edge: StillCall if any target callee fingerprint-matches
    // the helper, else Inlined if the target entry covers enough of the helper
    // features, else Missing.
    inline CallEdit label_call_edge(
            const FunctionFeatures &helper,
            const std::vector<FunctionFeatures> &target_callee_features,
            const FunctionFeatures &target_entry_features) {
        for (const auto &cf : target_callee_features) {
            if (fingerprint_match(helper, cf)) return CallEdit::StillCall;
        }
        if (feature_coverage(helper, target_entry_features) >= W_CALL_INLINED_COVERAGE) {
            return CallEdit::Inlined;
        }
        return CallEdit::Missing;
    }

    // Score contribution of one helper edge toward a target candidate.
    inline float call_edit_component(
            const FunctionFeatures &helper,
            const std::vector<FunctionFeatures> &target_callee_features,
            const FunctionFeatures &target_entry_features) {
        switch (label_call_edge(helper, target_callee_features, target_entry_features)) {
            case CallEdit::StillCall: return W_CALL_STILL;
            case CallEdit::Inlined:   return W_CALL_INLINED;
            case CallEdit::Missing:   return W_CALL_MISSING;
        }
        return 0.0f;
    }

    // Sum of call-edit contributions over all direct train helper edges for
    // one target candidate. Same for compact and flat channels (the helper
    // edges are train-side and do not change with the feature base).
    inline float call_edit_total(
            const std::vector<FunctionFeatures> &helper_edges,
            const std::vector<FunctionFeatures> &target_callee_features,
            const FunctionFeatures &target_entry_features) {
        float sum = 0.0f;
        for (const auto &h : helper_edges) {
            sum += call_edit_component(h, target_callee_features, target_entry_features);
        }
        return sum;
    }

    // ------------------------------------------------------------------
    // Match candidate record. One per resolved entry.
    // ------------------------------------------------------------------
    struct MatchCandidate {
        uint64_t entry = 0;
        // Raw target match addresses that resolved to this entry (>=1).
        std::vector<uintptr_t> raw_matches;
        // Channel scores computed from compact (own) and flat (flatten1)
        // train features respectively.
        float score_compact = 0.0f;
        float score_flat = 0.0f;
    };

    // Result of a successful accept.
    struct AcceptResult {
        uint64_t entry = 0;
        uintptr_t chosen_raw_match = 0;
        float score = 0.0f;
    };

    // ------------------------------------------------------------------
    // accept_candidates: implement plan accept algorithm steps 3-9.
    //
    // Pre-conditions (steps 1-2 performed by caller):
    //   * `candidates` already collected from function_table.containing()
    //     over all micro-window raw hits with entry >= limit_address.
    //   * score_compact / score_flat already populated per entry using
    //     compact vs flatten1 train features.
    //
    // Returns nullopt on any fail-closed path (steps 4, 7, 8); otherwise
    // returns the accepted entry, earliest raw match for it, and the
    // winning score (max of compact/flat for that entry).
    // ------------------------------------------------------------------
    inline std::optional<AcceptResult> accept_candidates(std::vector<MatchCandidate> candidates) {
        if (candidates.empty()) {
            return std::nullopt;
        }

        // Step 3: argmax per channel.
        const MatchCandidate *best_compact = &candidates.front();
        const MatchCandidate *best_flat = &candidates.front();
        for (const auto &c : candidates) {
            if (c.score_compact > best_compact->score_compact) {
                best_compact = &c;
            }
            if (c.score_flat > best_flat->score_flat) {
                best_flat = &c;
            }
        }

        const bool compact_positive = best_compact->score_compact > 0.0f;
        const bool flat_positive = best_flat->score_flat > 0.0f;

        // Step 4 / Step 5: agree rule, pick winning entry.
        uint64_t winning_entry = 0;
        if (compact_positive && flat_positive) {
            if (best_compact->entry != best_flat->entry) {
                // FAIL-CLOSED: compact and flat disagree on best entry.
                return std::nullopt;
            }
            winning_entry = best_compact->entry;
        } else if (compact_positive) {
            winning_entry = best_compact->entry;
        } else if (flat_positive) {
            winning_entry = best_flat->entry;
        } else {
            // No channel produced positive signal.
            return std::nullopt;
        }

        // Locate the winning candidate record.
        const MatchCandidate *winner = nullptr;
        for (const auto &c : candidates) {
            if (c.entry == winning_entry) {
                winner = &c;
                break;
            }
        }
        if (!winner) {
            return std::nullopt;
        }

        // Step 6: score(E) = max(score_compact(E), score_flat(E)).
        const float winning_score = std::max(winner->score_compact, winner->score_flat);

        // Step 7: second-best entry and gap < SCORE_M -> fail-closed (twin).
        if (candidates.size() >= 2) {
            float second_best = -std::numeric_limits<float>::infinity();
            for (const auto &c : candidates) {
                if (c.entry == winning_entry) {
                    continue;
                }
                const float s = std::max(c.score_compact, c.score_flat);
                if (s > second_best) {
                    second_best = s;
                }
            }
            if (winning_score - second_best < SCORE_M) {
                return std::nullopt;
            }
        }

        // Step 8: score(E) < SCORE_T -> fail-closed.
        if (winning_score < SCORE_T) {
            return std::nullopt;
        }

        // Step 9: accept; chosen_raw_match = earliest raw match for E.
        AcceptResult result;
        result.entry = winning_entry;
        result.score = winning_score;
        if (!winner->raw_matches.empty()) {
            uintptr_t earliest = winner->raw_matches[0];
            for (auto m : winner->raw_matches) {
                if (m < earliest) {
                    earliest = m;
                }
            }
            result.chosen_raw_match = earliest;
        }
        return result;
    }

} // namespace function_relocation::match_policy
