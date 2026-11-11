---
name: same-version-cross-platform-symbol-transfer
description: "Migrate engine symbols between same-version builds of the same game on different platforms/compilers (mac x64 ↔ Windows x64); calibrate every channel on known name pairs before applying, and fix the Itanium-vs-MSVC vtable dtor-slot offset."
---

# Same-version cross-platform symbol transfer

Both builds share source; symbols still differ because each build only exposes names through
**observable anchors**. Measure each channel's precision on the known-name pairs first, then apply.

## 0. Prerequisites (Ghidra MCP)

- Get both programs loaded:
  ```
  POST /load_program_from_project   {"path":"/name_in_project"}   # param IS `path`
  POST /switch_program?program=<name>                              # query param, not body
  ```
  `open_program` / `list_project_files` require GUI; `load_program_from_project` works headless.
  Scripts need `GHIDRA_MCP_ALLOW_SCRIPTS=1`; without it only single-edit tools work
  (`rename_function_by_address` with keys `function_address` + `new_name`).
- Script args arrive **comma-joined as one string**; scripts must do `args = raw[0].split(",")`.
- `get_current_program_info` / `list_open_programs` can be stale: verify the active program by
  probing a known address with `get_function_by_address`.

## 1. Ground truth is mandatory

Names present on both sides = supervision. Pair by unique tail:
```python
tail = lambda n: n.split("::")[-1]
```
Then compute coverage@precision for every channel. Keep only precision ≥ ~94%.

## 2. Channels, ranked (DST r759671 mac↔win, 2,183 gt pairs)

| channel | coverage | precision |
|---|---:|---:|
| string set, **mutually unique** (freq==1 both sides) | 680 | 94.7% |
| string strict (rare≤3, jaccard≥0.5, margin≥1) | 565 | 94.2% |
| callee-name set (margin≥2) | 219 | 95.4% |
| call-graph propagation (≥3 shared callees, margin≥2, 4 rounds) | 109 | 100% (n=13) |
| assert **(file,line)** 1:1 | 493 shared keys | 100% (8/8) |
| vtable slot alignment **after ABI fix** | — | 14/14 slot names agree |

**Falsified — never use:** address-order interpolation (build orders unrelated), caller-name sets
(0%), exact (instruction-count, block) buckets (truth inside 9%), within-class size rank (27%),
vtable alignment *without* the ABI fix (0/917), MSVC RTTI class naming (engine built `/GR-`,
only 7 `.?AV` strings).

## 3. vtable alignment: the ABI offset

```
Itanium (clang/GCC):  [offset-to-top=0][typeinfo][D1][D0][method0][method1]…
MSVC   (Windows):     [COL=0]         [scalar-deleting dtor][method0][method1]…
```
mac has **one extra dtor slot** ⇒ same-index comparison shifts everything by one and gives 0%.
Drop the leading dtor region on each side, then compare method slots at the same index.

Extract real vtables with `DstExportVtablesViaRefs.java` (constructor vptr stores) — naive
pointer-run scanning merges neighbouring tables (mac 613 vs 2,775; win 251 vs 575 on DST).

To name *derived* slots, attribute the vtable to a class:
1. **ctor/dtor name** — `DstVtableUsers.java`: scan every function for refs to known vtable
   addresses, keep rows whose name is `X::X` or `X::~X`.
2. **majority class of named slots** — needs *qualified* names (export the `q` field; unqualified
   names yield zero classes).

Match only same-class vtables; require ≥3 agreeing named slots and ratio ≥0.75; assign 1:1; propose
mac names for Windows slots that are still unnamed.

## 4. assert (file, line) — version-stable anchor

`AssertFunc(msg, line, file)` compiles as `LEA R8,[file]; LEA RCX,[msg]; MOV EDX,line; CALL ...`.
Backward-walk the call site **and** use `instruction.getReferencesFrom()` (op-object collection alone
misses LEA targets) → `DstExportAsserts.java`. Normalise each path to the part after `source/` and
unify separators, then match `(file,line)` 1:1.

## 5. Applying

- Slot targets are often not defined as functions: collect addresses →
  `DstDefineFunctionsFromList.java` (also comma-joined args) → then rename.
- Bulk: `DstApplyNames.java <tsv>,apply`; single: `rename_function_by_address`.
- Symbol names must contain **no spaces** (`unsigned long` → `unsigned_long`), else the applier
  aborts silently with empty output.

## 6. Accounting pitfall

`DstExportNames.java` has `if (f.isThunk()) continue;` — it drops 1,000+ named jump wrappers and
under-reports coverage by ~1 point. Use `DstExportNamesAll.java` for coverage metrics.
