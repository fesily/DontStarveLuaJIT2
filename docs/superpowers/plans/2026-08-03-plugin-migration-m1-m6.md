# Plugin Migration M1–M6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish plugin architecture Phase A: wire PluginHost into Inject/modmain, migrate features as plugins (M1–M4), slim trunks (M5), docs (M6). Keep L-A/L-B/L-G green.

**Architecture:** Path A static registry. Native dual-face plugins register in `RegisterBuiltinPlugins`; Lua plugins in `Mod/plugins/init.lua`. Host phases: EarlyNative → AfterLuaBridge → AfterModMain. Fail-fast deps; sticky unload; modinfo sole config.

**Tech Stack:** C++23, Frida Gum (existing hooks), Lua mod, ctest + L-G harness.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` (D1–D8, §5–§13).
- Path A single Injector DLL; no dynamic plugin libs (M7 out of scope).
- Fail-fast hard deps/conflicts/cycles; structured `PluginEvent`.
- Sticky unload default.
- No defensive existence checks (project convention).
- Existing regressions must stay green: `fork_save_lua`, host graph/option tests, L-G core when game present.
- Do not weaken tests to pass.
- Keep production behavior for each option identical when enabled/disabled.
- Prefer Lua-side orchestration for late features; native only where hooks already live.
- Commits frequent; skip project-wide full rebuilds unless needed; prefer clang++ unit tests + python L-G.

## Already done (do not re-do)

- M0: PluginHost + option rules + empty RegisterBuiltinPlugins + L-A/L-B tests.
- M-G: `tests/plugin_server` dedicated sim-pause harness green on local DST.

---

### Task 1: Wire PluginHost into Injector build + Inject EarlyNative

**Files:**
- Modify: `src/DontStarveInjector/CMakeLists.txt` — add core sources to Injector
- Modify: `src/DontStarveInjector/DontStarveInjector.cpp` — after config ready, `RegisterBuiltinPlugins` + resolve + `load_phase(EarlyNative)` (may still also call old paths until plugins migrate; dual-call OK only if plugins empty)
- Modify: `src/DontStarveInjector/gameModConfig.cpp` — stop hard side effects when host owns EarlyNative OR keep until M3 and document
- Create: `src/DontStarveInjector/core/PluginConfigBridge.hpp/.cpp` — build `ConfigView` from `GameJitModConfig` + defaults for early options (EnableVBPool, AngleBackend, NetworkOpt, AlwaysEnableMod fields already resolved)
- Test: extend L-A empty registry still passes; add unit test that resolve with empty registry after bridge is no-op

**Interfaces:**
- Consumes: `PluginHost`, `RegisterBuiltinPlugins`, `GameJitModConfig`
- Produces: Host singleton or stack host owned by Inject path; `ConfigView FromGameJitModConfig(const GameJitModConfig&)`

- [ ] **Step 1:** Write failing test for ConfigView bridge (VBPool true/false → config key)
- [ ] **Step 2:** Implement bridge + CMake link core into Injector
- [ ] **Step 3:** Call host from Inject after LoadGameModConfig resolve (order: resolve config → register → resolve plugins → EarlyNative). Empty registry ⇒ no behavior change.
- [ ] **Step 4:** Build/link smoke if possible; run host unit tests
- [ ] **Step 5:** Commit

---

### Task 2: Lua PluginHost + AfterModMain runner (L-C)

**Files:**
- Create: `Mod/plugins/host.lua` — pure Lua host mirror: register, resolve options, topo+priority, load/unload, events
- Create: `Mod/plugins/init.lua` — empty registry returning `{}` initially
- Modify: `Mod/modmain.lua` — after GameInjector assert, call `require`/`modimport` plugins host and `load_phase(AfterModMain)`; keep existing feature calls until each migrates (dual path: host empty + old code)
- Create: `tests/plugin/plugin_host_lua_spec.lua` + `tests/plugin/run_lua_host.py`
- Modify: `tests/CMakeLists.txt` — `plugin_host_lua` test

**Interfaces:**
- Produces: Lua `PluginHost` API matching C++ semantics for options/depends/priority/load
- Options via existing `GetModConfigData`

- [ ] **Step 1:** RED Lua host tests (topo, hard dep missing, option off, priority)
- [ ] **Step 2:** Implement host.lua + wire empty init.lua from modmain without removing old features
- [ ] **Step 3:** ctest/python runner green
- [ ] **Step 4:** Commit

---

### Task 3: M1 — migrate `save.fork` dual-face plugin

**Files:**
- Create: `Mod/plugins/save_fork.lua` — options EnableForkSave; when dedicated+hasluajit; load → existing `scripts/fork_save`
- Modify: `Mod/plugins/init.lua` — register save_fork
- Modify: `Mod/modmain.lua` — remove direct fork_save modimport block (host loads it)
- Native: if GameForkSave only exposes APIs (already), no EarlyNative needed; optional register sticky native no-op plugin for API documentation
- Test: L-E matrix EnableForkSave true/false in Lua host tests; `fork_save_lua` still green

- [ ] **Step 1:** RED enable-matrix rows for save.fork
- [ ] **Step 2:** Register plugin; remove hard-wired modmain path
- [ ] **Step 3:** Run fork_save_lua + lua host tests
- [ ] **Step 4:** Commit

---

### Task 4: M1 — migrate `sim.lagcomp` and `network.sim`

**Files:**
- Create: `Mod/plugins/sim_lagcomp.lua`, `Mod/plugins/network_sim.lua`
- Modify: `Mod/plugins/init.lua`, `Mod/modmain.lua` — remove hard-wired modimports
- Keep native GameSimHook/GameNetworkSim as API backends (lazy install unchanged)

- [ ] **Step 1:** RED matrix tests for both options
- [ ] **Step 2:** Implement plugins; strip modmain
- [ ] **Step 3:** Tests green
- [ ] **Step 4:** Commit

---

### Task 5: M2 — `network.rpc` + `network.entity` with depends

**Files:**
- Create native thin plugins or register in RegisterBuiltinPlugins:
  - `network.rpc`: EarlyNative calls `GameNetWorkHookRpc4` when NetworkOpt; AfterModMain Lua face for NetWorkOpt from modmain
- Create: `Mod/plugins/network_rpc.lua`, `Mod/plugins/network_entity.lua` (entity depends network.rpc)
- Modify: `DontStarveInjector.cpp` — stop unconditional `GameNetWorkHookRpc4()`; host EarlyNative owns it
- Modify: `modmain.lua` — remove NetWorkOpt hard-wiring

- [ ] **Step 1:** RED L-E entity cannot load when rpc off; hard dep test
- [ ] **Step 2:** Implement native+lua faces
- [ ] **Step 3:** Host graph + lua tests
- [ ] **Step 4:** Commit

---

### Task 6: M3 — `render.angle` + `render.vbpool` EarlyNative

**Files:**
- Create native plugins registered in RegisterBuiltinPlugins:
  - `render.vbpool`: EarlyNative → `DS_LUAJIT_set_vbpool_enabled` from config
  - `render.angle`: EarlyNative → `InitGameOpenGl` / AngleBackend
- Modify: `gameModConfig.cpp` `LoadGameModConfig` — remove hard VBPool/OpenGL side effects
- Modify: `modmain.lua` — remove late VBPool disable if owned by plugin (preserve disable semantics via config)

- [ ] **Step 1:** RED BufferNamePool still; config bridge EnableVBPool
- [ ] **Step 2:** Implement plugins; strip LoadGameModConfig side effects
- [ ] **Step 3:** Unit tests + compile
- [ ] **Step 4:** Commit

---

### Task 7: M4 — jit/gc/profiler/fps/tailcall Lua plugins

**Files:**
- Create: `Mod/plugins/jit_runtime.lua`, `jit_tailcall.lua`, `gc_policy.lua`, `debug_profiler.lua`, `fps_render.lua` (and encrypt/frostxx if thin merge into tailcall)
- Priorities per spec §7.3
- Modify: `modmain.lua` — remove corresponding hard-wired blocks; keep version UI / NoInjectorMain / crash clean

- [ ] **Step 1:** RED priority profiler before jit.runtime; option predicates
- [ ] **Step 2:** Migrate functions from modmain into plugins
- [ ] **Step 3:** Lua host tests + manual L-G if possible
- [ ] **Step 4:** Commit

---

### Task 8: M5 — trunk surface + L-F check

**Files:**
- Create: `tests/plugin/check_trunk_surface.py`
- Modify: `tests/CMakeLists.txt`
- Slim: `DontStarveInjector.cpp`, `gameModConfig.cpp`, `modmain.lua` to host-only feature paths

- [ ] **Step 1:** Write L-F script (forbidden call sites)
- [ ] **Step 2:** Fix trunks until L-F green
- [ ] **Step 3:** Full unit suite + L-G core if game available
- [ ] **Step 4:** Commit

---

### Task 9: M6 — contributor docs

**Files:**
- Create: `docs/plugin-system.md` — how to add a plugin (native + lua), option mapping table, phases, testing
- Optional: dummy plugin example in tests only

- [ ] **Step 1:** Write docs from inventory §7
- [ ] **Step 2:** Commit

---

### Task 10: Final verification

- [ ] Run host graph + option + lua host tests
- [ ] Run fork_save_lua
- [ ] Run L-G core profile if DST present
- [ ] Confirm L-F green
- [ ] Report remaining manual gaps

---
