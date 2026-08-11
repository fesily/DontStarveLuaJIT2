# function-relocation match v2 fixtures

This directory documents the synthetic match cases used by plan
`function-relocation-match-v2`.

## Layout

- `manifest.ini`: stable manifest for the case map
- `raw/`: tiny byte blobs for concrete cases
- `README.md`: fixture-to-test mapping

## Cases

1. `same_entry_multi_hit`
   - same entry produces multiple raw hits
   - covered by `test_micro_windows` (`same_entry_multi_hit` path)
2. `twin_identical_bodies_fail_closed`
   - two candidates share identical bodies
   - covered by `test_soft_score` (`twin_identical_reject`)
3. `twin_distinct_strings`
   - twins differ by embedded strings
   - covered by `test_soft_score` (`twin_distinct_strings_accept`)
4. `callee_inlined_into_parent`
   - callee body is absorbed into parent
   - covered by `test_virtual_flatten` (`test_inline_accept`)
5. `compact_flat_disagree`
   - compact and flat signals disagree
   - covered by `test_virtual_flatten` (`test_disagree_reject`)

## Manifest schema

Simple INI-like format:

```ini
schema=1

[case]
id=same_entry_multi_hit
title=Same entry, multi-hit
status=ready
notes=...
blob=raw/same_entry_multi_hit_a.inc
blob=raw/same_entry_multi_hit_b.inc
```

Supported keys:

- `schema` at top level
- `id`, `title`, `status`, `notes` inside `[case]`
- `blob` repeated for one file per line
- `blobs` as a comma-separated shorthand

## CTest wiring

The suite is registered in `tests/CMakeLists.txt` and tagged with the
`match_v2` label so it can be selected with `ctest -L match_v2`.

## Fixture files

- `raw/same_entry_multi_hit_a.inc`
- `raw/same_entry_multi_hit_b.inc`
- `raw/twin_identical_bodies_fail_closed_a.inc`
- `raw/twin_identical_bodies_fail_closed_b.inc`

The remaining cases are documented by the unit tests instead of extra raw
blobs.
