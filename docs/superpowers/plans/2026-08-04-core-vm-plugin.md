# Optional `plugin_core_vm` (VM + Signature) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Lua VM replace + Signature implementation into optional `plugin_core_vm` (id `core.vm`); inject and most feature plugins work without it; when present and VM path enabled, behavior matches today’s Signature → ReplaceLuaModule path.

**Architecture:** L0 orchestrates gum/config/plugins always. VM path is a separate branch: load `plugin_core_vm` dynamically (never static-link), call `ds_core_vm_run_signature_and_replace(...)`; missing/false → log and continue. Signature co-located with VM in the same DLL. `DisableJITWhenServer` only disables the VM branch, not DynamicPluginLoader.

**Tech Stack:** C++23, CMake ninja multi-config RelWithDebInfo, existing `ds::plugin` DynamicPluginLoader/Host, Frida Gum re-export from Injector, function_relocation (no second Gum), ctest + `tests/plugin_server/run_dedicated_sim_pause.py` (L-G).

**Spec:** `docs/superpowers/specs/2026-08-04-core-vm-plugin-design.md` (revised optional semantics, commit `6b15fa5`)

## Global Constraints

- **core.vm is optional** — missing/failed module ⇒ log + skip VM; **do not abort inject**.
- **Feature plugins load independently of VM** — fix L0 so `DisableJITWhenServer` does not `return` before DynamicPluginLoader.
- Signature lives **with** VM in `plugin_core_vm` (not a separate mandatory service).
- L0 **never** static-links `plugin_core_vm`; only LoadLibrary/dlopen.
- No second Frida Gum in the plugin (`/NODEFAULTLIB:frida-gum.lib` on Win; use Injector re-exports).
- Fail-fast only for true L0 hard failures (gum init, etc.), not for missing core.vm.
- Incremental: each task buildable; L-G green after inject-path changes.
- modinfo option names unchanged (`LuaVmType`, `EnabledGenGC`, `DisableJITWhenServer`).
- YAGNI: no hot-swap VM, no multi-VM market.

## File map (end state)

| Path | Role |
|---|---|
| `src/DontStarveInjector/plugins/plugin_core_vm/plugin_core_vm.cpp` | Module init + optional C bootstrap export |
| `src/DontStarveInjector/plugins/plugin_core_vm/GameLua.cpp` (+ hpp/type/framework/def) | VM replace |
| `src/DontStarveInjector/plugins/plugin_core_vm/DontStarveSignature.cpp` (+ related) | Signature |
| `src/DontStarveInjector/core/CoreVmBootstrap.hpp` | L0 helper: find/load module, call bootstrap, no fail-fast |
| `src/DontStarveInjector/DontStarveInjector.cpp` | Inject order: plugins always; VM branch optional |
| Feature plugins | Unchanged except lagcomp already degrades without symbols |

---

### Task 1: L0 inject — plugins always; VM path gated (V-S0)

**Files:**
- Modify: `src/DontStarveInjector/DontStarveInjector.cpp` (`Inject`)
- Test: L-G dedicated; optionally force `DisableJITWhenServer` true in a one-off env/config if harness allows — at minimum code-path review + L-G with default config

**Interfaces:**
- Produces: helper in anonymous namespace or `core/`:
  ```cpp
  // true = run signature + ReplaceLuaModule
  bool VmPathEnabled(bool isClient, const GameJitModConfig *cfg);
  // Implementation:
  //   if (!isClient && cfg && cfg->DisableJITWhenServer) return false;
  //   return true; // unless DontStarveInjectorDisable already returned earlier
  ```

**Current bug to fix:**

```cpp
// TODAY (wrong product): early return skips plugins entirely
if (!isClient) {
    auto config = GameJitModConfig::instance();
    if (config && config->DisableJITWhenServer) {
        return;  // DELETE this full-function return
    }
}
```

**Target structure (keep existing steps; reorder only as needed):**

```cpp
DONTSTARVEINJECTOR_API void Inject(bool isClient) {
    // ... existing: disable flag, init_ctx, logging, crash check, steam ...
    // REMOVE early return on DisableJITWhenServer

    ictx->DontStarveInjectorIsClient = isClient;
    // logging setup ...

    // Config before plugins (move LoadGameModConfig earlier if still after ReplaceLuaModule)
    LoadGameModConfig();

    // ALWAYS: PluginHost + DynamicPluginLoader + resolve + EarlyNative
    // (same block as today, just ensure it is not behind DisableJITWhenServer)

    const bool vm = VmPathEnabled(isClient, GameJitModConfig::instance() ? &*GameJitModConfig::instance() : nullptr);
    if (vm) {
        // existing: load lua51, scan, SignatureUpdater, ReplaceLuaModule
        // (still in Injector until later tasks move them)
    } else {
        spdlog::info("Lua VM path disabled — continuing with native plugins only");
    }

    DisableScriptZip(); // keep if still required when VM off — if it depends on replace, gate it
}
```

**Order note:** Today `LoadGameModConfig()` is **after** ReplaceLuaModule. For V-S0:

1. Keep Signature/Replace where they are **if** still in Injector, **but** remove the early `return` so that when you later enable plugins-before-VM, the early return is already gone.  
2. Minimal V-S0 that satisfies success criterion 5:  
   - Delete `return` on `DisableJITWhenServer`.  
   - Wrap **only** the block from `loadlib(lua51)` through `ReplaceLuaModule` (+ `replace_game_branch_flag_to_dev` if VM-only) in `if (VmPathEnabled(...))`.  
   - Ensure PluginHost block runs **unconditionally** after config (move `LoadGameModConfig` before plugin block if not already).

Concrete step: read current `Inject` fully; apply:

- [ ] **Step 1: Add `VmPathEnabled`**

```cpp
static bool VmPathEnabled(bool isClient) {
    if (isClient) {
        return true;
    }
    auto config = GameJitModConfig::instance();
    if (config && config->DisableJITWhenServer) {
        return false;
    }
    return true;
}
```

- [ ] **Step 2: Remove early server return; gate VM block only**

```cpp
// DELETE:
// if (!isClient) { auto config = ...; if (DisableJITWhenServer) return; }

// AFTER logging/crash/steam, BEFORE or AFTER plugins — for V-S0 keep plugins after VM
// as today if less risky, BUT wrap lua51..ReplaceLuaModule:

if (VmPathEnabled(isClient)) {
    auto lua51 = loadlib(lua51_name);
    // ... signature + ReplaceLuaModule as today ...
} else {
    spdlog::info("Lua VM path disabled (e.g. DisableJITWhenServer) — skipping signature/replace");
}

LoadGameModConfig(); // if not already called
// PluginHost + load_all + resolve + EarlyNative  // MUST run even when !VmPathEnabled
```

**If plugins currently sit after ReplaceLuaModule:** leaving them after the gated VM block is enough for V-S0 as long as they are **outside** the `if (VmPathEnabled)` and the early `return` is gone.

- [ ] **Step 3: Build + L-G**

```bash
cmake --build builds/ninja-multi-vcpkg --config RelWithDebInfo --target Injector
# stage Injector.dll
LG_T_HOLD=5 python tests/plugin_server/run_dedicated_sim_pause.py
```

Expected: `[lg] PASS`; plugins still `DynamicPluginLoader loaded`.

- [ ] **Step 4: Commit**

```bash
git commit -m "fix(inject): DisableJITWhenServer gates VM only, not plugins (V-S0)"
```

---

### Task 2: Optional core.vm loader shell (V-S1)

**Files:**
- Create: `src/DontStarveInjector/core/CoreVmBootstrap.hpp`
- Create: `src/DontStarveInjector/core/CoreVmBootstrap.cpp`
- Modify: `src/DontStarveInjector/CMakeLists.txt` — add `core/CoreVmBootstrap.cpp` to Injector
- Create: `src/DontStarveInjector/plugins/plugin_core_vm/plugin_core_vm.cpp` — **stub** first: init + stub `ds_core_vm_run_signature_and_replace` returning false or calling back into Injector symbols temporarily
- Modify: `DontStarveInjector.cpp` — call bootstrap helper when `VmPathEnabled`

**Interfaces:**

```cpp
// core/CoreVmBootstrap.hpp
#pragma once
#include <cstdint>
#include <string>

namespace ds::core_vm {

struct BootstrapArgs {
    bool is_client = true;
    uintptr_t lua_module_base = 0;
    const char *main_path = nullptr;
};

// Loads plugins/plugin_core_vm.{dll,so} if not already loaded.
// Returns false if module missing or init fails — never aborts process.
bool EnsureCoreVmModuleLoaded();

// Returns function pointer or nullptr.
using RunSigReplaceFn = bool (*)(const BootstrapArgs *args);
RunSigReplaceFn GetRunSignatureAndReplaceFn();

// Convenience: Ensure + call; false = skip VM (caller logs).
bool TryRunSignatureAndReplace(const BootstrapArgs &args);

} // namespace ds::core_vm
```

```cpp
// plugin export (C)
extern "C" __declspec(dllexport) // or visibility default
bool ds_core_vm_run_signature_and_replace(const ds::core_vm::BootstrapArgs *args);
// Stub in V-S1: return false until S2/S3 move code; OR call existing
// SignatureUpdater + ReplaceLuaModule if still in Injector via GetProcAddress from Injector — avoid.
// V-S1 stub: implement full path still in Injector; helper only loads module for init registration;
// TryRunSignatureAndReplace: if fn null, fall back to in-process LegacyRunSignatureAndReplace() in Injector.
```

**V-S1 pragmatic fallback (required for green builds):**

```cpp
bool TryRunSignatureAndReplace(const BootstrapArgs &args) {
    if (auto *fn = GetRunSignatureAndReplaceFn()) {
        return fn(&args);
    }
    // Fallback while implementation still in Injector (Tasks 3–4 not done):
    return LegacySignatureAndReplaceInInjector(args);
}
```

Extract today’s lua51/signature/Replace block into `LegacySignatureAndReplaceInInjector` in `DontStarveInjector.cpp` or a small `GameLuaBootstrapLegacy.cpp` still linked into Injector until Task 4 deletes it.

- [ ] **Step 1: Implement CoreVmBootstrap load path**

Win: `LoadLibraryExW` on `<injector_dir>/plugins/plugin_core_vm.dll` then `GetProcAddress(..., "ds_core_vm_run_signature_and_replace")` and `ds_plugin_module_init` if not using DynamicPluginLoader yet.

Prefer: rely on **DynamicPluginLoader** already loading `plugin_core_vm` when present; `EnsureCoreVmModuleLoaded` only `GetModuleHandleA("plugin_core_vm.dll")` / `dlsym(RTLD_DEFAULT, ...)`.

- [ ] **Step 2: Stub plugin_core_vm**

```cpp
// plugin_core_vm.cpp
// register id "core.vm", AlwaysOn, EarlyNative priority 0 (or high priority low number)
// load(): no-op
// export ds_core_vm_run_signature_and_replace → return false; // forces legacy fallback until S2
```

CMake: `ds_add_dynamic_plugin(plugin_core_vm ...)` on **all platforms** (like save_fork), link Injector + spdlog; no ANGLE.

- [ ] **Step 3: Wire Inject to TryRunSignatureAndReplace**

- [ ] **Step 4: L-G with and without staging core.vm stub**

```bash
# with stub DLL: still PASS via legacy fallback
# rename DLL away: still PASS via legacy fallback
```

- [ ] **Step 5: Commit**

```bash
git commit -m "feat(core.vm): optional module loader + stub plugin (V-S1)"
```

---

### Task 3: Move Signature into plugin_core_vm (V-S2)

**Files:**
- Move: `DontStarveSignature.cpp` / `.hpp`, `SignatureJson.cpp` / `.hpp` (if only used by signature — verify with `rg`)
- Modify: `plugin_core_vm` CMake sources
- Modify: Injector CMake — remove those TUs
- Implement: `ds_core_vm_run_signature_and_replace` **partial**: run SignatureUpdater only + still need Replace in Injector **or** full if GameLua still in Injector callable

**Problem:** `ReplaceLuaModule` still in Injector after S2. Options:

**A (recommended for S2):** `ds_core_vm_run_signature_and_replace` runs **signature only**, returns signatures via out-params — messy ABI.

**B (cleaner):** S2 moves signature **and** keeps calling `ReplaceLuaModule` imported from Injector if still exported — reverse dependency bad.

**C (plan choice):** In S2, `ds_core_vm_run_signature_and_replace` implements **signature + replace** only after GameLua moved; until then S2 moves signature TUs into plugin but **L0 legacy still does both** until S3. That means S2 is “link ownership move” with plugin containing signature code **called from plugin only after S3**.

**Practical S2 (link ownership + dead code prevention):**

1. Move Signature sources into `plugins/plugin_core_vm/`.  
2. Implement `ds_core_vm_run_signature_and_replace` to:
   - run `SignatureUpdater::create_or_update`
   - call `ReplaceLuaModule` — **still requires GameLua in same DLL**  
3. Therefore **merge S2+S3 if split is false economy** — plan allows **one task “move Signature+GameLua together”** if engineer prefers; otherwise S2 only moves files that compile inside plugin **without** switching call path (plugin links signature but L0 still has copies) — **forbidden** (duplicate).

**Locked approach:** Task 3 moves **Signature + GameLua + framework + def together** (spec S2+S3 combined for link correctness). Task 4 is GameLuaModule split only.

Rename tasks for clarity:

### Task 3: Move Signature + GameLua into plugin_core_vm (V-S2+V-S3)

**Files:**
- Move into `plugins/plugin_core_vm/`:
  - `GameLua.cpp`, `GameLua.hpp`, `GameLuaType.hpp` (if not needed by L0 `gameModConfig` — **GameLuaType may stay shared header in L0** if gameModConfig includes it; prefer keep `GameLuaType.hpp` in L0 or `core/` if small)
  - `GameLuaInjectFramework.lua` + generated `.c` + CMake custom command for lua2c
  - `GameLua.def` (MSVC)
  - `LuajitVariantNames.hpp`
  - `DontStarveSignature.cpp/.hpp`
  - `SignatureJson.cpp/.hpp` if exclusive
- Audit `lua_fake.cpp`, `lua_debugger_helper.cpp`: move only if exclusive to VM; else keep L0 with comment
- Modify: Injector SOURCES remove moved files
- Modify: `plugin_core_vm` target: sources + `function_relocation` + spdlog + nlohmann_json as needed + `/NODEFAULTLIB:frida-gum.lib` + `GUM_STATIC=1`
- Implement real `ds_core_vm_run_signature_and_replace`:
  ```cpp
  bool ds_core_vm_run_signature_and_replace(const BootstrapArgs *args) {
      // loadlib lua51, SignatureUpdater::create_or_update, ReplaceLuaModule, cleanup
      // same logic as extracted legacy block
      return success;
  }
  ```
- Remove `LegacySignatureAndReplaceInInjector` body; `TryRun` only calls plugin export; if null, log skip (**no** in-process fallback after this task)

**GetGameLuaContext:** export from **plugin_core_vm** (`DS_INJECTOR_CXX_API` equivalent dllexport). Update `plugin_sim_lagcomp` to resolve from `plugin_core_vm.dll` or `GetProcAddress`; if missing, entity_get_raw_ptr no-ops.

**GameLua.def:** attach to `plugin_core_vm` on MSVC (not Injector).

- [ ] **Step 1: Move TUs + fix includes**
- [ ] **Step 2: Implement bootstrap export with full signature+replace**
- [ ] **Step 3: Delete legacy in-Injector implementation**
- [ ] **Step 4: Fix lagcomp / any GetGameLuaContext imports**
- [ ] **Step 5: Build all plugins + Injector; dumpbin Injector has no ReplaceLuaModule; core.vm has exports**
- [ ] **Step 6: L-G PASS; client smoke if available**
- [ ] **Step 7: Commit**

```bash
git commit -m "feat(core.vm): move Signature + GameLua into optional plugin_core_vm"
```

---

### Task 4: GameInjector open ownership (V-S4)

**Files:**
- Modify: `GameLuaModule.cpp` — split or relocate `luaopen_GameInjector` into plugin_core_vm TU (e.g. `GameInjectorOpen.cpp` under plugin)
- Keep config cascade / `LoadGameJitModConfig*` in L0 (GameLuaModule or gameModConfig)
- Ensure `GameLua.cpp` registration of `luaopen_GameInjector` resolves symbol from same DLL

**Rules:**

- Business trampolines (fork, net_sim, vbpool, …) stay GetProcAddress-style; can live in core.vm’s open **or** L0 open — **prefer core.vm open only when VM loaded**; when VM skipped, game may not get GameInjector module (acceptable per degradation matrix)
- When VM path skipped, do not register GameInjector

- [ ] **Step 1: Move `luaopen_GameInjector` + VM-related `set_function` binds into plugin**
- [ ] **Step 2: Leave cascade/parser in Injector**
- [ ] **Step 3: L-G + unit**
- [ ] **Step 4: Commit**

```bash
git commit -m "refactor(core.vm): luaopen_GameInjector owned by plugin_core_vm"
```

---

### Task 5: DisableJITWhenServer / missing core.vm verification matrix (hardening)

**Files:**
- Tests: extend plugin server harness or add unit for `VmPathEnabled`
- Optional: env `DS_LUAJIT_FORCE_NO_CORE_VM=1` for CI negative path

- [ ] **Step 1: Document and automate**

| Scenario | Expect |
|---|---|
| core.vm present, VM enabled | Signature+replace run; L-G PASS |
| core.vm absent, VM enabled | Warn; plugins load; L-G PASS |
| VM disabled (DisableJITWhenServer) | No signature; plugins load; L-G PASS |

- [ ] **Step 2: Manual or scripted rename plugin_core_vm.dll and re-run L-G**
- [ ] **Step 3: Commit test notes / harness flag if added**

```bash
git commit -m "test(core.vm): optional module degradation matrix"
```

---

### Task 6: Docs + deploy (V-S5)

**Files:**
- Modify: `docs/plugin-system.md` — core.vm optional, deploy list includes `plugin_core_vm.dll` for JIT
- Modify: architecture note that D3 is superseded for VM **implementation** ownership
- RegisterBuiltinPlugins comment list

- [ ] **Step 1: Docs**
- [ ] **Step 2: Grep Injector for leftover GameLua.cpp / DontStarveSignature in CMake SOURCES — empty**
- [ ] **Step 3: Full ctest plugin_/config_ + L-G**
- [ ] **Step 4: Commit**

```bash
git commit -m "docs(plugin): core.vm optional deployment and plugin-system notes"
```

---

## Spec coverage

| Spec item | Task |
|---|---|
| V-S0 plugins always; DisableJITWhenServer → VM only | Task 1 |
| Optional LoadCoreVm; no fail-fast | Task 2 |
| Move Signature + GameLua | Task 3 |
| GameInjector split | Task 4 |
| Degradation matrix / negative tests | Task 5 |
| Docs / deploy | Task 6 |
| Success: omit core.vm without killing inject | Tasks 1–3, 5 |
| Success: most plugins without VM | Task 1 + existing plugins |
| Signature co-located with VM | Task 3 |

## Self-review notes

- Combined physical move of Signature+GameLua in Task 3 avoids half-moved link graphs (spec S2/S3).  
- No “fail-fast missing core.vm” anywhere.  
- Legacy fallback exists only until Task 3 completes; Task 3 removes it.  
- `GameLuaType.hpp` may remain L0 if `gameModConfig` needs it — do not force circular plugin include.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-04-core-vm-plugin.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session with executing-plans checkpoints  

Which approach?
