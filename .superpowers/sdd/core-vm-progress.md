# SDD Progress — optional plugin_core_vm

Plan: docs/superpowers/plans/2026-08-04-core-vm-plugin.md
Spec: docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md
Base HEAD at start: f2cb4ce

## Tasks
- Task 1: complete (commits f2cb4ce..3292039, review clean)
- Task 2: complete (commits 3292039..56834d5, review clean)
- Task 3: complete (commits 56834d5..c2a5cfa, review clean after fix)
- Task 4: complete (verification only at c2a5cfa; ownership already from Task 3; L-G PASS; no code commit)
- Task 5: complete (degradation matrix present/absent/vm_disabled; L-G PASS ×3; harness --scenario + env flags)
- Task 6: complete (docs + deploy notes; greps clean; unit ctest + L-G present PASS)

## Task 3 (V-S2+V-S3) — DONE

Signature+GameLua in plugin_core_vm; no legacy fallback; L-G PASS.
See core-vm-task-3-report.md.

## Task 4 (V-S4) — DONE

GameInjector open ownership verified in plugin_core_vm; cascade L0; trampolines GetProcAddress; VM-skip soft; L-G PASS.
See core-vm-task-4-report.md. No product code changes (Task 3 already moved TUs).
Task 4: complete (verification only on c2a5cfa, review clean)

## Task 5 (V-S5) — DONE

Degradation matrix verified on dedicated L-G:
present (vm=jit + GameInjector), absent (rename + soft skip + plugins), vm_disabled (FORCE_DISABLE_VM / DisableJITWhenServer gate).
See core-vm-task-5-report.md.
Task 5: complete (commits c2a5cfa..120e339, review clean)

## Task 6 (V-S5 docs) — DONE

Optional core.vm documented in `docs/plugin-system.md` + D3 supersession note; deploy list recommends `plugin_core_vm.dll` for JIT.
See core-vm-task-6-report.md.
Task 6: complete (commit docs(plugin): core.vm optional deployment and plugin-system notes)
