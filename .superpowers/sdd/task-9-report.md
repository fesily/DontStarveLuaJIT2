# Task 9 Report — M6 contributor docs

**Status:** DONE  
**Date:** 2026-08-03  
**Commit:** `04d2b036e8621df83dcb183d5bab4a19a9b8f72f`

## Summary

Added `docs/plugin-system.md`: Path A contributor guide grounded in live
`RegisterBuiltinPlugins` / `Mod/plugins/*` / host tests (not speculative APIs).

## Deliverable

| File | Role |
|---|---|
| `docs/plugin-system.md` | How to add native + Lua plugins; phases; option rules; inventory table; testing |
| `.superpowers/sdd/task-9-report.md` | This report |

## Guide sections

1. **L0 vs plugins** — VM/AlwaysEnableMod/host vs feature modules  
2. **Phases** — EarlyNative → AfterLuaBridge (reserved) → AfterModMain; resolve + fail-fast  
3. **Native plugin** — `IPlugin` in `RegisterBuiltinPlugins.cpp`, ConfigView bridge, dual-face  
4. **Lua plugin** — `Mod/plugins/<name>.lua` + `init.lua` + existing modmain host wire  
5. **Option rules** — AllOf/AnyOf/AlwaysOn/StringEq·Neq + Lua table forms  
6. **Inventory** — depends/conflicts/priority from current code (hard dep: `network.entity` → `network.rpc`)  
7. **Examples** — `save.fork`, `network.rpc`/`network.entity`, `render.vbpool`/`render.angle`  
8. **Testing** — L-A graph, L-B options, bridge, L-C/E lua host, L-D regressions, L-F trunk, L-G dedicated  
9. **Checklist** + key paths  

## Non-goals / notes

- No dummy test plugin (optional in brief).  
- `steam.workshop` / AfterLuaBridge plugins not registered yet — documented as reserved/spec-only.  
- Docs-only; no production behavior change.

## Verification

- Guide content cross-checked against:
  - `RegisterBuiltinPlugins.cpp` (3 native plugins)
  - `Mod/plugins/init.lua` + each plugin manifest
  - `PluginTypes.hpp` / `PluginOptionRules` / `host.lua` option forms
  - `tests/CMakeLists.txt` ctest names for L-A…L-G
- Commit: `04d2b03`

## Checklist

- [x] Write `docs/plugin-system.md` from inventory §7 + live code  
- [x] Commit  
- [x] Report at `.superpowers/sdd/task-9-report.md`
