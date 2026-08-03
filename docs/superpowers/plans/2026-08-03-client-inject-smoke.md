# Client Inject Smoke Implementation Plan

> **For agentic workers:** Execute task-by-task. Spec: `docs/superpowers/specs/2026-08-03-client-inject-smoke-design.md`.

**Goal:** Phase-1 automated client inject smoke (LG_CLIENT_* tokens) + CTest; Phase-2 config profiles after Phase-1 green.

**Architecture:** Python orchestrator launches `dontstarve_steam_x64` with inject; thin client probe mod emits log tokens; default world path is **P1b dedicated LAN + stress auto-spawn** for reliability, with `--mode offline` for P1a experiments.

**Tech Stack:** Python 3, DST client/server, existing L-G / stress_test patterns.

## Global Constraints

- No Playwright/Appium/image click as primary oracle.
- SKIP without game; LG_REQUIRE_GAME=1 enforces FAIL on skip.
- Tokens primary: `[lc_probe] TOKEN NAME body`
- Full LuaJit2 must be loadable (AlwaysEnableMod / workshop); probe is client_only.
- Fail-fast if Injector missing when game present.
- Phase-2 config write is Task 5–6, not Phase-1 DoD.

---

### Task 1: Client probe mod

**Files:**
- Create: `tests/plugin_client/probe_mod/modinfo.lua`
- Create: `tests/plugin_client/probe_mod/modmain.lua`

**Tokens:** `LG_CLIENT_INJECT_OK|MISSING`, `LG_CLIENT_MOD_LOADED`, `LG_CLIENT_PLUGINS_OK`, `LG_CLIENT_WORLD_READY`

- [ ] Emit tokens with `_G`/rawget (strict-safe)
- [ ] World ready: SimPostInit or ThePlayer / TheWorld.ismastersim client path / InGamePlay

### Task 2: Orchestrator Phase-1 (P1b default)

**Files:**
- Create: `tests/plugin_client/run_client_inject_smoke.py`
- Create: `tests/plugin_client/README.md`

**Behavior:**
- resolve_game_dir / find client exe
- install probe; force_enable probe
- start dedicated LGPluginTest (reuse plugin_server helpers or subprocess to run_dedicated with shorter hold disabled — better: start dedicated only until Ready, then client)
- start client with stress-like flags + force_enable probe (+ optional LuaJit2 name)
- also install/enable stress_test_bot for LAN auto-connect+spawn OR fold minimal connect into probe
- wait tokens; hold; kill

**Exit:** 0 PASS, 1 FAIL, 2 SKIP

### Task 3: CTest + dry-run SKIP

**Files:**
- Modify: `tests/CMakeLists.txt`

### Task 4: Local green run (or document P1a fallback)

### Task 5–6: Phase-2 mod_config + profiles (after Phase-1)

---
