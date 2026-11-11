---
name: cmake-target-rename-sweep
description: "Rename a CMake target repo-wide: enumerate definitions, classify callers, update live references only, verify via regenerated target list. Not for adding targets."
---

# Rename a CMake target and prove nothing broke

Trigger: a target name is misleading (e.g. a bare verb like `create` sitting next
to `update_signatures`) and must be renamed repo-wide.

## 1. Enumerate definitions

```
grep -rn "add_custom_target(<old>\b\|add_executable(<old>\b" .
```

Multi-platform projects often define the **same** target name in several
branches (`if(APPLE)` / `else()` Linux / `else()` Windows). Rename every branch;
keep each `COMMAND` / `DEPENDS` body byte-identical so the diff is pure renaming.

## 2. Sweep callers, not substrings

The word is usually overloaded (tool subcommand, enum value, prose). Classify
each hit before touching it:

| Hit shape | Action |
|---|---|
| `--target <old>`, `-t <old>`, `ninja <old>`, `add_dependencies(... <old>)`, `DEPENDS <old>`, `if(TARGET <old>)` | rename — real caller |
| `<tool> <old>` CLI arg, `MODE=<old>`, `SignatureMode::Create` | leave — tool naming is decoupled |
| Source comments naming the tool mode | leave |
| CHANGELOG history entries | leave — they record the name at that time |

Recursive search over every script/CI file:

```
grep -rn --include=*.txt --include=*.cmake --include=*.py --include=*.sh \
     --include=*.yml --include=*.yaml \
     -E "TARGET +<old>\b|--target +<old>\b|DEPENDS +<old>\b" \
     --exclude-dir=3rd --exclude-dir=builds --exclude-dir=vcpkg .
```

Update live docs/comments that name the **build target** (e.g. a test docstring
saying "exactly like the shipped `<old>` and `update_signatures` build targets"),
then add one CHANGELOG bullet per language stating the rename and that the tool
mode/CLI argument name is unchanged.

## 3. Verify by regenerating, not by compiling

```
cmake --build <build-dir> --target help      # forces reconfigure, prints targets
```

Assert: the new name is present, the old bare name absent, rc=0. Compiling the
target is unnecessary — a rename is a configure-time fact.

## Environment note (this workstation)

`cmake` is not on PATH in the bash tool; the exec'able copy is VS-bundled:

```python
cm = r'C:\Program Files\Microsoft Visual Studio\18\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
subprocess.run([cm, '--build', build_dir, '--target', 'help'])
```

Call it through `python -c` — direct execution from bash reports
`command not found` even though `ls` sees the file.
