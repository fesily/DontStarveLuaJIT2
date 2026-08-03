# Client Host Smoke Design — DontStarveLuaJIT2

**Date:** 2026-08-03  
**Status:** Draft for review  
**Scope:** Add a **client-host** automated path: single `dontstarve_steam_x64` process hosts an offline world in-process (no separate dedicated). Complements existing P1b (dedicated + LAN client).

Related:

- Client inject smoke: `docs/superpowers/specs/2026-08-03-client-inject-smoke-design.md`
- Harness: `tests/plugin_client/run_client_inject_smoke.py`
- Host API reference (vanilla): `dst-scripts/scripts/screens/redux/mainscreen.lua` `MainScreen:OnHostButton`
- Create-server UI chain (not primary): `ServerCreationScreen:Create` / `TheSystemService:StartDedicatedServers`

---

## 1. Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| H1 | Goal | Prove inject + LuaJit2 + plugins on **client-hosted** world (`ismastersim` / client-hosted server) |
| H2 | Process model | **Single process**: steam client only; **no** dedicated sibling |
| H3 | World entry | Lua automation of host path (`TheNet:StartServer` + `LOAD_SLOT`), **not** UI click / Playwright |
| H4 | Relationship to P1b | **Additive** mode; P1b remains default for “join external server” |
| H5 | Caves | **Out of scope** for v1 (single Master / forest only) |
| H6 | Empty slot / worldgen | v1 prefers **existing save slot**; auto-worldgen only as documented fallback if needed |
| H7 | Stress bot | Host mode does **not** enable LAN auto-join (`stress_test_bot` off or host-specific helper without join) |

---

## 2. Problem

Current L-C default (`--mode p1b`):

1. Start offline dedicated `LGPluginTest`
2. Start client
3. `stress_test_bot` LAN-searches and joins dedicated
4. Client is **not** the host (`ismastersim` false on client world authority path)

Missing path users care about:

- Player launches client → Host → in-process server → enter world  
- Injector + PluginHost + config run on the **hosting** client process

---

## 3. Goals / non-goals

### Goals (v1)

1. CLI mode to run **client-host only** smoke.  
2. No dedicated process started by orchestrator.  
3. After FE, Lua starts offline server on a fixed slot and loads world.  
4. Same core inject tokens as Phase-1: `LG_CLIENT_MOD_LOADED`, `LG_CLIENT_INJECT_OK`, `LG_CLIENT_PLUGINS_OK`, `LG_CLIENT_WORLD_READY`, hold → `LG_CLIENT_STABLE`.  
5. Host-specific proof token: `LG_CLIENT_HOST_OK` when client-hosted / mastersim is true.  
6. Optional `--profile` still applies (Phase-2 config write before launch).  
7. SKIP without game binary (same policy as P1b).

### Non-goals (v1)

- Caves / multi-shard client host  
- Full `ServerCreationScreen` UI wizard automation  
- Replacing P1b  
- Online / Steam auth host  
- Multi-bot stress on client-host  

---

## 4. Architecture

```text
run_client_inject_smoke.py --mode host
        │
        ├─ (optional) apply_profile
        ├─ ensure Injector in bin64
        ├─ install plugin_lc_probe (+ host helper if split)
        └─ start ONLY dontstarve_steam_x64
                -offline -debug_random_data
                -force_enable_mods=plugin_lc_probe[;plugin_lc_host]
                        │
                        ▼
              FE ready → host Lua:
                TheNet:StartServer(false, slot, serverdata)
                StartNextInstance(LOAD_SLOT, slot)
                        │
                        ▼
              world ready + ismastersim / client-hosted
              TOKEN LG_CLIENT_* + LG_CLIENT_HOST_OK
                        │
                        ▼
              hold T_hold → kill client
```

| Artifact | Role |
|---|---|
| Orchestrator | New `run_p1_host()` path; no dedicated lifecycle |
| Probe / host helper | Emit tokens; perform StartServer+LOAD_SLOT |
| Profiles | Unchanged Phase-2 `mod_config` |

---

## 5. Host entry strategy (Lua)

### 5.1 Primary (mirror debug Host button)

Vanilla pattern (`MainScreen:OnHostButton`):

```lua
local start_in_online_mode = false
local slot = N  -- configurable, default 1
ShardSaveGameIndex:LoadSlotEnabledServerMods()
KnownModIndex:Save()
if TheNet:StartServer(start_in_online_mode, slot, ShardSaveGameIndex:GetSlotServerData(slot)) then
    DisableAllDLC()
    StartNextInstance({ reset_action = RESET_ACTION.LOAD_SLOT, save_slot = slot })
end
```

Automation hooks from **MainScreen** (or GamePostInit + short delay) so we avoid MultiplayerMainScreen “Mods installed” popup chain (same rationale as stress bot).

### 5.2 Slot policy (v1)

| Case | Behavior |
|---|---|
| Slot has existing offline world | Host + LOAD_SLOT (preferred) |
| Slot empty | Fail with clear log **or** optional fallback: delete/init minimal serverdata then LOAD_SLOT / worldgen path — only if primary blocked |
| Env `LC_HOST_SLOT` | Override slot index (default `1`) |

Document prerequisite: local machine should have a usable offline slot for smoke, **or** implement empty-slot fallback in the same milestone if discovery shows OnHostButton already handles empty slots safely.

### 5.3 Spawn

After world load:

- If lobby / no character: reuse `ResumeRequestLoadComplete` skip + `TheNet:SendSpawnRequestToServer` (copy from stress bot Part 2 **only**, not Part 1 LAN join).  
- Host may already land in-world depending on slot state; probe must tolerate both.

### 5.4 What not to call (v1)

- `TheSystemService:StartDedicatedServers` multi-level path (caves / external dedicated children)  
- `+connect` / `StartClient` to self (that is join, not host identity for our proof)  
- `stress_test_bot` full mod (LAN search will steal control)

---

## 6. Tokens / contract

| Token | Meaning |
|---|---|
| `LG_CLIENT_MOD_LOADED` | probe loaded |
| `LG_CLIENT_INJECT_OK` | `GameInjector ~= nil` |
| `LG_CLIENT_PLUGINS_OK` | inject present / host healthy signal |
| `LG_CLIENT_HOST_OK` | **new** — `TheNet:GetServerIsClientHosted()` and/or `TheWorld.ismastersim` after world |
| `LG_CLIENT_HOST_FAIL` | StartServer failed or not client-hosted when world ready |
| `LG_CLIENT_WORLD_READY` | world / player / InGamePlay |
| `LG_CLIENT_CONFIG*` | Phase-2 samples (unchanged) |
| `LG_CLIENT_STABLE` | orchestrator after hold |

### Timeouts (defaults; overridable via env)

| Param | Default | Notes |
|---|---|---|
| `T_inject` | 90s | same as P1b |
| `T_host` | 120s | StartServer → host ok (new) |
| `T_world` | 300s | worldgen may be slower than LAN join |
| `T_hold` | 30s | same |
| `T_shutdown` | 60s | kill client only |

### Exit codes

Same as P1b: `0` PASS, `1` FAIL, `2` SKIP.

---

## 7. Orchestrator CLI

```text
--mode p1b     # default: dedicated + LAN client (existing)
--mode host    # NEW: client-host only
--mode offline # alias of host OR deprecated stub → host (pick one in impl; prefer alias)
```

Host mode must:

- **Not** call `start_dedicated`
- force_enable: `plugin_lc_probe` (+ optional `plugin_lc_host` if split from probe)
- still support `--profile`
- still require Injector when game present

CTest: keep default target as P1b **or** add `plugin_client_host_smoke` second target (prefer **second target** so CI/local can run either).

---

## 8. Implementation slices

| Slice | Deliverable | Gate |
|---|---|---|
| H-0 | Design + plan | this doc approved |
| H-1 | Host Lua path in probe or `plugin_lc_host` | StartServer+LOAD_SLOT emits `LG_CLIENT_HOST_OK` or clear fail |
| H-2 | Orchestrator `--mode host` | no dedicated; contract green on local with existing slot |
| H-3 | README + optional CTest target | documented runbook |
| H-4 | Empty-slot fallback (only if H-2 blocked) | empty slot also green |

---

## 9. Success criteria

| ID | Criterion | Proof |
|---|---|---|
| S-H1 | Single client process | orchestrator does not spawn dedicated |
| S-H2 | Inject/mod/plugins | existing LG_CLIENT inject tokens |
| S-H3 | Client-hosted | `LG_CLIENT_HOST_OK` |
| S-H4 | World + hold | `LG_CLIENT_WORLD_READY` + stable hold |
| S-H5 | SKIP without game | same as P1b |

---

## 10. Risks

| Risk | Mitigation |
|---|---|
| Empty slot / long worldgen | Prefer existing slot; raise `T_world`; optional H-4 fallback |
| FE popups block host | Hook MainScreen early; suppress known mod-warning if required |
| `StartServer` fails offline skins | Mirror OnHostButton offline inventory force-load if present |
| Conflict with stress bot LAN join | Do not enable stress_test_bot in host mode |
| Slot pollution | Use dedicated smoke slot via `LC_HOST_SLOT` when available; document |

---

## 11. Spec self-review

| Check | Result |
|---|---|
| Placeholders | Empty-slot auto-worldgen deferred to H-4 only if needed — explicit |
| Consistency | Additive to P1b; tokens extend Phase-1 |
| Scope | Single-process host, no caves |
| Ambiguity | `--mode host` is the name; offline stub becomes alias |

---

## 12. Approval

User intent confirmed: **Client Host (single process)**, not caves-first.  
Implement after user review of this written spec.
