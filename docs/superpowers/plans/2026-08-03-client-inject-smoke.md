# Client Inject Smoke Implementation Plan

> **For agentic workers:** Execute task-by-task. Spec: `docs/superpowers/specs/2026-08-03-client-inject-smoke-design.md`.

**Goal:** Phase-1 automated client inject smoke (LG_CLIENT_* tokens) + CTest; Phase-2 config profiles after Phase-1 green.

**Architecture:** Python orchestrator launches `dontstarve_steam_x64` with inject; thin client probe mod emits log tokens; default world path is **P1b dedicated LAN + stress auto-spawn** for reliability, with `--mode offline` for P1a experiments.

**Tech Stack:** Python 3, DST client/server, existing L-G / stress_test patterns.

**Status:** **COMPLETE** (2026-08-03)

| Slice | Gate | Result |
|---|---|---|
| M-C0 | dry SKIP | OK |
| M-C1 | Phase-1 P1b green | PASS (`675305a`) |
| M-C2 | CTest + README | OK |
| M-C3 | mod_config + profiles | PASS (`af8b9bf`) |
| M-C4 | defaults + minimal | both PASS local |

## Global Constraints

- No Playwright/Appium/image click as primary oracle.
- SKIP without game; LG_REQUIRE_GAME=1 enforces FAIL on skip.
- Tokens primary: `[lc_probe] TOKEN NAME body`
- Full LuaJit2 must be loadable (AlwaysEnableMod / workshop); probe is client_only.
- Fail-fast if Injector missing when game present.
- Phase-2 config write is Task 5–6, not Phase-1 DoD.

---

### Task 1: Client probe mod — DONE

**Files:**
- `tests/plugin_client/probe_mod/modinfo.lua`
- `tests/plugin_client/probe_mod/modmain.lua`

**Tokens:** `LG_CLIENT_INJECT_OK|MISSING`, `LG_CLIENT_MOD_LOADED`, `LG_CLIENT_PLUGINS_OK`, `LG_CLIENT_WORLD_READY`, Phase-2 `LG_CLIENT_CONFIG` / `LG_CLIENT_CONFIG_SRC`

- [x] Emit tokens with `_G`/rawget (strict-safe)
- [x] World ready: SimPostInit / PlayerPostInit / InGamePlay poll
- [x] Phase-2: sample main mod options via `KnownModIndex:LoadModConfigurationOptions`

### Task 2: Orchestrator Phase-1 (P1b default) — DONE

**Files:**
- `tests/plugin_client/run_client_inject_smoke.py`
- `tests/plugin_client/README.md`

**Behavior delivered:**
- resolve_game_dir / find client + dedicated exe
- install probe + stress_test_bot
- start dedicated LGPluginTest until ready marker
- client: `-offline -debug_random_data -force_enable_mods=plugin_lc_probe;stress_test_bot` (`;` separator)
- wait inject/mod/plugins → world → hold → kill
- Exit: 0 PASS, 1 FAIL, 2 SKIP

### Task 3: CTest + dry-run SKIP — DONE

- `tests/CMakeLists.txt` → target `plugin_client_inject_smoke`
- No game → SKIP (exit 2 mapped to 0 unless `LG_REQUIRE_GAME=1` / `LC_REQUIRE_GAME=1`)

### Task 4: Local green run — DONE

P1b local PASS (Phase-1 commit `675305a`):
`LG_CLIENT_MOD_LOADED` + `INJECT_OK` + `PLUGINS_OK` + `WORLD_READY` + hold → `LG_CLIENT_STABLE`

P1a offline left as `--mode offline` stub (not required after P1b green).

### Task 5–6: Phase-2 mod_config + profiles — DONE

**Files:**
- `tests/plugin_client/mod_config.py` — KLEI Lua brace-aware read/write
- `tests/plugin_client/profiles/defaults.json` — `{}`
- `tests/plugin_client/profiles/minimal.json` — risk-off overrides
- orchestrator `--profile` / `LC_PROFILE` + `verify_profile_tokens`

**Local proof (S-C5 / S-C6):**
- `--profile minimal` → all sampled `LG_CLIENT_CONFIG` match → PASS
- `--profile defaults` → empty profile skip assert → Phase-1 contract PASS

---

## Success criteria map

| ID | Criterion | Status |
|---|---|---|
| S-C1 | `LG_CLIENT_INJECT_OK` | PASS |
| S-C2 | mod/plugins tokens | PASS |
| S-C3 | world + hold + stable | PASS |
| S-C4 | SKIP without game | PASS |
| S-C5 | config write + config tokens | PASS |
| S-C6 | defaults + minimal matrix | PASS |

## Commits

- `675305a` feat(test): add client inject smoke harness (L-C Phase-1)
- `af8b9bf` feat(test): Phase-2 client mod config profiles + assert
- `a91bb70` chore: drop accidental plugin_client pycache from tree

## Runbook

```bash
# Phase-1
set LC_T_HOLD=15
python tests/plugin_client/run_client_inject_smoke.py --cluster LGPluginTest

# Phase-2 matrix
python tests/plugin_client/run_client_inject_smoke.py --cluster LGPluginTest --profile defaults
python tests/plugin_client/run_client_inject_smoke.py --cluster LGPluginTest --profile minimal

# config helpers
python tests/plugin_client/mod_config.py show
python tests/plugin_client/mod_config.py apply --profile minimal
python tests/plugin_client/mod_config.py restore
```

## Out of scope (explicit)

- `network_on` / `render_preview` optional profiles (design §6.4 optional)
- P1a offline full automation
- Server `modoverrides` profile family
- CI without GPU/game
