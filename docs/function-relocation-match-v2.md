# Function Relocation Match v2

Developer note for the soft match path added in plan
`function-relocation-match-v2`. This covers what changed, how it fails
closed, what stays frozen, how to run the tests, and what was deferred.

## Soft match path

When the target module has a non-empty `FunctionTable`,
`fix_func_address_by_signature` (Signature.cpp) takes a new soft path
instead of the old unique-byte uniqueness gate plus LCS fallback.

The soft path has four layers, built one on top of the next.

### Micro-windows

`MicroWindow.hpp` generates sliding instruction windows over the
clamped Nucleus body of the training function. Each window is 5 to 16
instructions long, sliding by one instruction within each contiguous
segment. The stream is split at `X86_INS_CALL` and unconditional
`X86_INS_JMP` so no window ever contains a call or jump as an interior
instruction. Conditional branches stay inside windows. Windows with
fewer than 5 non-wildcardized distinguishing bytes are dropped.

Hex encoding reuses the existing section-based `create_signature`
wildcard rules for RIP-relative displacements, call immediates, and
module-address mov-immediates. It does not embed callee prologue bytes
into parent windows.

### Vote plus features

Each micro-window pattern is scanned against target memory. Every raw
hit is resolved to a candidate entry through
`function_table.containing(raw_match)`. An entry accumulates a vote
score of `min(distinct_window_hits, 8) * 1.0` into both the compact and
flat channels.

On top of the vote, each candidate gets four feature scores:

- `W_CONST`: `10.0 * |train_strings intersect target_strings| / max(1, |train_strings|)`
- `W_IMM`: `4.0 * |stable_imms_train intersect stable_imms_target| / max(1, |stable_imms_train|)`
- `W_SIZE`: `+2.0` if `target_size` is in `[0.5 * train_size, 3.0 * train_size]`, else 0
- `W_CALL`: per helper edge, StillCall `+1.0`, Inlined `+0.8`, Missing `-0.5`

Stable immediates are values with absolute magnitude under `0x10000` or
in the known TValue/type constant set
`{0x10,0x18,0x20,0x28,0x30,0x38,0x40,0x48,0x50,0x58,0x08,0x00}`.

Locked constants live in `MatchPolicy.hpp` under
`function_relocation::match_policy`. `Signature.cpp` pulls them in with
a using directive and pins every value with `static_assert`. The names
are `SCORE_T = 3.0`, `SCORE_M = 1.5`, and the `W_*` weights.

### Flatten1

`flatten1_features(own, helper_features)` builds a virtual flattened
feature set by unioning the training function's own consts and imms
with those of its direct helper callees. The `FunctionTable` and
`Function::size` are never mutated. The flat features exist only as a
transient `FunctionFeatures` value passed to the dual-channel
resolver.

Helper eligibility is enforced in `extract_helper_edges`:

1. callee address in same module text
2. callee has a `Function` with size greater than 0
3. callee size at most 256, or callee not in export known_functions
4. depth exactly 1, no recursion

### Call-edit labels

Three pure functions in `MatchPolicy.hpp` label each helper edge:

- `fingerprint_match(helper, callee)`: StillCall when the callee's
  const plus imm set is a superset of the helper's and the helper has at
  least one distinguishing feature.
- `feature_coverage(helper, target)`: Inlined when the target entry's
  feature multiset covers at least 50 percent of the helper's string
  and imm features.
- Otherwise: Missing.

`call_edit_total` sums the contributions over all helper edges. The
same total applies to both channels because helper edges are
train-side and do not change with the feature base.

### Dual-channel agree

`resolve_multi_hit_entry` scores every candidate entry on two
channels:

```
score_compact = vote + const(train_own) + imm(train_own) + size(train_own) + call_edit
score_flat    = vote + const(train_flat) + imm(train_flat) + size(train_own) + call_edit
```

Both channels use `train_own.size` for the size band. If both channels
have a positive best on different entries, the resolver returns
`nullopt` and the match fails closed.

### Accept algorithm

`accept_candidates` runs the full decision:

1. best_compact_entry is the argmax of score_compact, best_flat_entry
   is the argmax of score_flat.
2. If both channels have positive best on different entries, fail
   closed.
3. The winning entry E is the agreed entry, or the only channel that
   produced candidates.
4. `score(E) = max(score_compact(E), score_flat(E))`.
5. If a second-best entry exists and `score(E) - score(second) <
   SCORE_M`, fail closed.
6. If `score(E) < SCORE_T`, fail closed.
7. Otherwise accept E. `chosen_raw_match` is the earliest raw match
   among hits that resolved to E. `pattern_offset = E -
   chosen_raw_match`. Return E.

### limit_signature

`limit_signature` shortens `signature_info->pattern` in 3-character
steps. Under the soft path it calls `soft_revalidate_pattern`, which
re-runs the same `build_feature_candidates` plus `accept_candidates`
pipeline on the shortened pattern. It only accepts if the result entry
matches `soft_winning_entry` from the full-length scan. A shortened
pattern that matches a different entry is rejected, so shortening is a
refinement of the existing decision, never a re-pick.

The legacy `scan_by_signature` uniqueness path still runs when the
`FunctionTable` is empty.

## Fail-closed twins

The soft path never returns a wrong entry. Three fail-closed guards
enforce this.

1. Compact versus flat disagree: if the two channels pick different
   entries and both have positive signal, reject.
2. Twin margin: if a second-best entry exists and the winner's margin
   is under `SCORE_M = 1.5`, reject.
3. Absolute threshold: if the winner's score is under `SCORE_T = 3.0`,
   reject.

On reject, `scan_by_micro_windows` calls
`micro_window::summarize_candidates` and logs best, second, and margin
through spdlog. The reject leaves `SignatureInfo` unchanged, so there
is no partial mutation.

## SignatureInfo wire frozen

`SignatureInfo` in `src/FunctionRelocation/Signature.hpp` keeps
exactly three fields:

```cpp
struct SignatureInfo {
    uintptr_t offset;
    std::string pattern;
    int pattern_offset;
};
```

The `NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT` macro lists only
`offset`, `pattern`, `pattern_offset`. No scores are serialized. No
version bump was added for scoring. The signatures JSON schema is
unchanged.

`tests/function_relocation/test_schema_freeze.cpp` guards this. It
includes `Signature.hpp`, round-trips a `SignatureInfo` through
nlohmann JSON, and asserts the serialized object has exactly the three
keys and no others.

## How to run the synthetic tests

The header-only tests do not link frida-gum or function_relocation,
so they build with a bare g++ command from the worktree root:

```bash
g++ -std=c++23 -I src/FunctionRelocation \
    tests/function_relocation/test_match_accept_policy.cpp -o /tmp/test_match_accept_policy
g++ -std=c++23 -I src/FunctionRelocation \
    tests/function_relocation/test_micro_windows.cpp -o /tmp/test_micro_windows
g++ -std=c++23 -I src/FunctionRelocation \
    tests/function_relocation/test_soft_score.cpp -o /tmp/test_soft_score
g++ -std=c++23 -I src/FunctionRelocation \
    tests/function_relocation/test_virtual_flatten.cpp -o /tmp/test_virtual_flatten
g++ -std=c++23 -I src/FunctionRelocation \
    tests/function_relocation/test_orchestration.cpp -o /tmp/test_orchestration
g++ -std=c++23 -I src/FunctionRelocation \
    tests/function_relocation/test_schema_freeze.cpp -o /tmp/test_schema_freeze
```

Each binary runs with no arguments and exits 0 on success.

Under a full CMake configure, the same tests are registered as ctest
targets in `tests/CMakeLists.txt`:

```bash
cmake --preset ninja-multi-vcpkg
cmake --build builds/ninja-multi-vcpkg --preset ninja-vcpkg-release
ctest --test-dir builds/ninja-multi-vcpkg --build-config Release -R 'match_accept_policy|micro_windows|soft_score|virtual_flatten|orchestration|schema_freeze'
```

The synthetic fixtures under
`tests/function_relocation/fixtures/match_v2/` cover the five plan
cases: same_entry_multi_hit, twin_identical_bodies_fail_closed,
twin_distinct_strings, callee_inlined_into_parent, and
compact_flat_disagree. The fixture loader and CMake wiring are owned
by the parallel fixture task.

## Deferred: graph bipartite matcher

The plan explicitly defers a global graph bipartite matcher to later
work. The current soft path is local: it scores each candidate entry
against the single training function in isolation. A graph matcher
that solves an assignment problem across all unmatched functions
simultaneously is not part of this ship. The guardrails in
`.omo/plans/function-relocation-match-v2.md` list "Graph worklist /
global bipartite matcher" under Must NOT have for this plan.

The deferred work, tracked as C7, would:

- Build a bipartite graph of training functions versus candidate
  entries.
- Solve a maximum-weight matching so a strong candidate for function A
  that is also a weak twin for function B does not steal B's true entry.
- Keep the local accept policy as a pre-filter.

Until C7 lands, the local fail-closed guards handle the twin and
disagree cases that a global matcher would otherwise resolve.
