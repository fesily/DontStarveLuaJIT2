# Config Ownership Boundaries Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Split game-option ownership so L0 only holds base identity/policy, core.vm owns VM keys, business plugins own feature keys — no L0 kill-switch on VM policy, no permanent L0 business schema inventory.

**Architecture:** Domain `OptionKeys` constants; schema register = key SSOT per domain; Inject order keeps base alive when VM disabled; cascade after plugin schema registration for full key set.

**Tech Stack:** C++23, existing `ds::config` cascade, `plugin_core_vm`, PluginHost, ctest under `tests/plugin/`.

**Spec:** `docs/superpowers/specs/2026-08-05-config-ownership-boundaries-design.md`

## Global Constraints

- core.vm remains **optional** (missing ⇒ log/skip replace, inject continues).
- modinfo option **names** unchanged.
- Fail-fast on schema conflict (including `allowed_sources`).
- L-G present green after inject/VM-path tasks.
- Do not put `InjectorConfig` process flags into game cascade.
- Prefer constants over magic strings for all option keys touched in a task.

## File map (end state additions)

| Path | Role |
|------|------|
| `src/DontStarveInjector/config/BaseOptionKeys.hpp` | L0 identity + AlwaysEnableMod constants |
| `src/DontStarveInjector/plugins/plugin_core_vm/VmOptionKeys.hpp` | LuaVmType, EnabledGenGC, DisableJITWhenServer |
| `plugins/*/…OptionKeys.hpp` | Per-plugin business keys (as touched) |
| `config/ConfigSchema.cpp` | Base seed only |
| `plugin_core_vm.cpp` | Register VM schema |
| `DontStarveInjector.cpp` | No L0 VM early-out |
| `config/sources/EnvOrCmdSource.cpp` | VM emits via Vm keys / helper |

---

### Task 1: OptionKeys headers + wire L0 base constants (OB-S0)

**Files:**
- Create: `src/DontStarveInjector/config/BaseOptionKeys.hpp`
- Create: `src/DontStarveInjector/plugins/plugin_core_vm/VmOptionKeys.hpp`
- Modify: `config/ConfigSchema.cpp` RegisterCore — use BaseOptionKeys for identity + AlwaysEnableMod; **leave VM keys in place this task** but add VmOptionKeys and use them in RegisterCore for VM entries (prepare move)
- Modify: `ResolvedConfig.hpp` accessors to use constants
- Test: extend `test_config_schema` — core seed still has expected keys (document current set)

- [ ] **Step 1:** Add headers:

```cpp
// BaseOptionKeys.hpp
#pragma once
#include <string_view>
namespace ds::config::keys {
inline constexpr std::string_view kModmainPath = "modmain_path";
inline constexpr std::string_view kModname = "modname";
inline constexpr std::string_view kModid = "modid";
inline constexpr std::string_view kSaveFile = "save_file";
inline constexpr std::string_view kAlwaysEnableMod = "AlwaysEnableMod";
}
// VmOptionKeys.hpp
#pragma once
#include <string_view>
namespace ds::config::keys {
inline constexpr std::string_view kLuaVmType = "LuaVmType";
inline constexpr std::string_view kEnabledGenGC = "EnabledGenGC";
inline constexpr std::string_view kDisableJITWhenServer = "DisableJITWhenServer";
}
```

- [ ] **Step 2:** Replace string literals in RegisterCore + ResolvedConfig + Luajit/Env sources with constants (behavior unchanged).

- [ ] **Step 3:** `test_config_schema` + build Injector; commit  
  `refactor(config): OptionKeys constants for base and VM keys`

---

### Task 2: Inject soft-disable VM (OB-S1)

**Files:**
- Modify: `DontStarveInjector.cpp` — remove / replace block that returns from Inject when `disable_jit_when_server()`
- Modify: `core/CoreVmBootstrap.cpp` and/or `plugin_core_vm.cpp` — if server && DisableJITWhenServer, skip `ds_core_vm_run_signature_and_replace` (log + soft)
- Test: unit if possible; **L-G present** still PASS; document server+flag behavior

- [ ] **Step 1:** Read current early-out (~DontStarveInjector.cpp:148–155).

- [ ] **Step 2:** L0 continues past that check; pass server flag into bootstrap args if needed.

- [ ] **Step 3:** core.vm path:

```cpp
// pseudocode in bootstrap or plugin load
if (is_server && view DisableJITWhenServer)
  log skip replace; return true/soft false without aborting Inject;
```

- [ ] **Step 4:** L-G present; commit  
  `fix(inject): DisableJITWhenServer is VM soft-skip, not L0 abort`

---

### Task 3: VM schema ownership → plugin_core_vm (OB-S2)

**Files:**
- Modify: `config/ConfigSchema.cpp` — **remove** LuaVmType, EnabledGenGC, DisableJITWhenServer from RegisterCoreOptionSchema
- Modify: `plugin_core_vm.cpp` — register those three schemas in `ds_plugin_module_init` (defaults match modinfo)
- Modify: cascade timing so save parse still sees VM keys:
  - **Preferred:** register core.vm module (and others) before full resolve used for Host; OR re-apply save partial after module_init
- Modify: tests that assume RegisterCore has 4+ VM keys — update expected counts
- L-G present

- [ ] **Step 1:** Failing test: after RegisterCore only, `find("LuaVmType") == nullptr`.

- [ ] **Step 2:** Register in plugin_core_vm; ensure loader runs core.vm init before Host resolve that needs VM defaults (identity resolve may stay early).

- [ ] **Step 3:** If save file had LuaVmType and was parsed only on first resolve before plugins: add **second apply** of cached save partial after module_init, or delay full resolve.

- [ ] **Step 4:** Commit  
  `refactor(config): VM option schema owned by plugin_core_vm`

---

### Task 4: Env/Luajit VM emits only with VM schema (OB-S3)

**Files:**
- Modify: `EnvOrCmdSource.cpp`, `LuajitConfigSource.cpp` — emit VM keys via `VmOptionKeys`; if schema lacks key at apply time, partial still emits and apply_partial ignores unknown (OK) **or** gate emit on schema.find
- Ensure `allowed_sources` for VM keys set in plugin_core_vm register (All or as today)
- Tests: resolve with/without VM schema entries

- [ ] Commit  
  `refactor(config): VM source fields keyed by VmOptionKeys`

---

### Task 5: Remove L0 business schema seed (OB-S4)

**Files:**
- Modify: `ConfigSchema.cpp` — empty or delete `RegisterBuiltinBusinessOptionSchema`
- Modify: `DontStarveInjector.cpp` / `gameModConfig.cpp` — stop calling it; rely on plugin `module_init` + order:
  1. load_all plugins (schema register)
  2. resolve or re-apply save/env with full schema
  3. Host resolve
- Modify: each business plugin already registers schema — verify masks match former seed
- Tests: config_view_build / resolve still green; L-G present

- [ ] **Step 1:** Assert plugins register NetworkOpt, EnableNetSim, etc.

- [ ] **Step 2:** Remove builtin business seed; fix order.

- [ ] **Step 3:** Commit  
  `refactor(config): drop L0 RegisterBuiltinBusinessOptionSchema`

---

### Task 6: Accessors + grep gate (OB-S5)

**Files:**
- Modify: `ResolvedConfig.hpp` — deprecate or relocate VM accessors docs; Injector must not call them
- Modify: business plugins — introduce small OptionKeys headers when touching
- Grep: no raw `"LuaVmType"` etc. outside VmOptionKeys / tests
- Update design spec status → Implemented
- L-G present

- [ ] Commit  
  `chore(config): enforce domain OptionKeys; document ownership`

---

## Spec coverage

| Spec § | Task |
|--------|------|
| §3.1 L0 keys only | T3, T5 |
| §3.2 VM keys core.vm | T3, T4 |
| §3.3 business plugins | T5 |
| §4 soft disable | T2 |
| §6 OptionKeys | T1, T6 |
| §9 success criteria | T6 verification |

## Execution

After commit of this plan: subagent-driven or inline per user choice.
