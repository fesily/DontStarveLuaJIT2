# Client Inject Smoke Design — DontStarveLuaJIT2

**Date:** 2026-08-03  
**Status:** Draft for review  
**Scope:** Phase-1 automated **client** proof that Injector + mod/plugins load and reach a stable in-world state; **Phase-2** automated **mod configuration_options** mutation for profiled smoke.

Related:

- Dedicated L-G: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` §12.10  
- Existing client bot scaffold: `tests/stress_test_mod/`  
- Config storage: `modconfiguration_*` under Klei `client_save/mod_config_data` (see `gameModConfig.cpp`)

---

## 1. Decisions (locked for this design)

| # | Decision | Choice |
|---|---|---|
| C1 | Phase-1 goal | **Core inject smoke only** (user confirmed) |
| C2 | UI automation suite | **Not** Playwright / Appium / image click. Process + Lua probe + log tokens (same philosophy as dedicated L-G). |
| C3 | World entry | **P1a offline client world first**; **P1b dedicated + connect + auto-spawn** as documented fallback |
| C4 | What must load | **Full DontStarveLuaJit2 mod** (workshop / AlwaysEnableMod path) **plus** a thin client probe mod for markers |
| C5 | Phase-2 (next) | **Automated mod configuration_options mutation** before client launch (profile matrix) |
| C6 | Runner shell | Optional **pytest** later; Phase-1 may be a single Python entry like L-G |

---

## 2. Goals / non-goals

### Phase-1 goals

1. Start `dontstarve_steam_x64` with inject layout present.  
2. Prove `GameInjector ~= nil`.  
3. Prove DontStarveLuaJit2 modmain / PluginHost AfterModMain ran without fatal Lua error.  
4. Prove client reaches a **world-ready** state and holds **≥ T_hold** without process death.  
5. Clean process teardown.  
6. No game binary → **SKIP** (not silent PASS).  

### Phase-2 goals (follow-up, in-scope for design, not Phase-1 DoD)

1. Programmatically write **mod configuration_options** values for this mod before launch.  
2. Run the same client inject smoke under **named profiles** (e.g. defaults, all experimental off, NetworkOpt on).  
3. Assert profile-specific expectations where observable (plugin load / inject still green).  

### Non-goals

- Multi-bot stress (existing `stress_test_mod` roadmap).  
- Pixel/UI clicking, WinAppDriver, Airtest as primary oracle.  
- Full Angle/VBPool visual correctness.  
- Forcing client smoke on CI without GPU/game install.

---

## 3. Architecture

```text
                  ┌─────────────────────────────┐
                  │ run_client_inject_smoke.py  │
                  │  prep → launch → wait → hold│
                  └─────────────┬───────────────┘
           Phase-2 only:        │
           write mod config ────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         ▼                      ▼                      ▼
  Injector in bin64     workshop / Mod copy      client probe mod
  Winmm layout          DontStarveLuaJit2        TOKEN markers
         │                      │                      │
         └──────────────────────┴──────────────────────┘
                                ▼
                    dontstarve_steam_x64 (+ offline / +connect)
                                ▼
                    client_log + TOKEN LG_CLIENT_*
```

| Artifact | Path (target) | Role |
|---|---|---|
| Orchestrator | `tests/plugin_client/run_client_inject_smoke.py` | Process life, wait tokens, exit codes |
| Client probe | `tests/plugin_client/probe_mod/` | `client_only_mod`; emit `LG_CLIENT_*` |
| Config writer (Phase-2) | `tests/plugin_client/mod_config.py` | Read/write `modconfiguration_*` for this mod |
| Profiles (Phase-2) | `tests/plugin_client/profiles/*.json` | Named option maps |
| README | `tests/plugin_client/README.md` | GAME_DIR, inject, timeouts, profiles |
| CTest | `plugin_client_inject_smoke` | SKIP without game |

Reuse:

- Path discovery patterns from `tests/plugin_server/run_dedicated_sim_pause.py` and `tests/stress_test_mod/run_stress_test.py`.  
- Client launch flags already used by stress harness (`-offline`, `-debug_random_data`, `-force_enable_mods=...`) — re-verify against current client before hardcoding.  
- Token oracle style from L-G (`[lg_probe] TOKEN NAME ...`).

---

## 4. Phase-1 boot contract

| Step | Action | Pass signal |
|---|---|---|
| 1 Prep | Ensure Injector (+ Winmm) in game `bin64`; install probe; force-enable probe + ensure LuaJit2 enabled (AlwaysEnableMod / force_enable / modoverrides as appropriate) | files present |
| 2 Launch | Start steam client with documented args | pid alive |
| 3 Inject | Probe or log: `GameInjector ~= nil` | `LG_CLIENT_INJECT_OK` |
| 4 Mod / plugins | LuaJit2 main ran; PluginHost AfterModMain completed without Failed required plugins (or probe observes host) | `LG_CLIENT_MOD_LOADED`, `LG_CLIENT_PLUGINS_OK` |
| 5 World | Offline world ready **or** connected+spawned (fallback path) | `LG_CLIENT_WORLD_READY` |
| 6 Hold | ≥ `T_hold` (default **30s**), process alive, no fatal log patterns | `LG_CLIENT_STABLE` |
| 7 Shutdown | Terminate client; optional dedicated if used | exit accepted; no hang past `T_shutdown` |

### Timeouts (defaults)

| Param | Default |
|---|---|
| `T_inject` | 90s |
| `T_world` | 300s |
| `T_hold` | 30s |
| `T_shutdown` | 60s |

### Skip vs fail

| Env | Result |
|---|---|
| No `DST_GAME_DIR` / no client exe | **SKIP** (ctest: exit 0 unless `LG_REQUIRE_GAME=1`) |
| Game present, contract broken | **FAIL** |
| All markers + hold | **PASS** |

### Fatal patterns (secondary)

Access violation / pure virtual / unexpected process death before `LG_CLIENT_STABLE`.  
Do not treat `DisplayError` alone as inject success.

---

## 5. World entry strategy

### P1a — Offline client world (primary)

- Launch client offline / local.  
- Probe advances past FE into a world when possible (hooks similar in spirit to stress_test auto-spawn, but for offline host).  
- **If blocked** by FE auth/UI without stable Lua hooks: document and switch to P1b.

### P1b — Dedicated + connect (fallback)

- Start offline dedicated (reuse L-G cluster or stress cluster).  
- Client `+connect 127.0.0.1:<port>` (port from cluster `server.ini`).  
- Reuse / thin-wrap `stress_test_bot` auto-spawn (`ResumeRequestLoadComplete` skip lobby).  
- Markers still from **client probe** (not only server).

Phase-1 implementation order: **implement P1a; if not green in one iteration, land P1b without expanding scope**.

---

## 6. Phase-2: Mod configuration_options mutation (follow-up)

### 6.1 Why

Plugin architecture is **modinfo-driven**. Client smoke that only uses whatever last UI save left on disk cannot prove:

- defaults / experimental off  
- NetworkOpt on  
- EnableVBPool on (client EarlyNative)  
- etc.

Automated **config write → launch → smoke** is the missing gate.

### 6.2 Storage reality (current game)

- Client saved options live under Klei data, typically:

  `Documents/Klei/DoNotStarveTogether/<steamid>/client_save/mod_config_data/modconfiguration_<modname>[_dev]`

- Native cascade already understands this layout (`gameModConfig.cpp`: `GetModConfigDataDir` / `GetModConfigDataFileName`).  
- Server shards may use `modoverrides.lua` — **Phase-2 client smoke targets client_save modconfiguration first**.  
- Format: game-persisted table (often via `PersistentString` / encoded blob — harness must **read an existing file from a known-good client save** or call into game APIs if format is opaque).

### 6.3 Config writer API (target)

```text
tests/plugin_client/mod_config.py

load_mod_config(mod_id) -> dict[option_name, value]
write_mod_config(mod_id, overrides: dict, *, base="defaults"|"current") -> path
apply_profile(profile_name) -> path
```

Rules:

1. **Only touch DontStarveLuaJit2** (workshop id / mod folder name aliases as already used by native config identity).  
2. Prefer **merge overrides** onto known defaults from `modinfo.configuration_options` (parse `Mod/modinfo.lua` via luajit or a checked-in defaults JSON generated offline).  
3. Fail-fast if write path cannot be resolved (no silent “ran with wrong config”).  
4. After write, Phase-1 smoke must observe options either via:  
   - probe reading `GetModConfigData` and emitting `LG_CLIENT_CONFIG <key>=<value>` tokens, or  
   - native early log of resolved `GameJitModConfig` (optional).  

### 6.4 Profiles (initial set)

| Profile | Intent | Overrides (illustrative) |
|---|---|---|
| `defaults` | modinfo defaults | (empty overrides) |
| `minimal` | all experimental / risky off | EnableVBPool=false, EnableNetSim=false, EnableLagCompensation=false, EnableForkSave=false, NetworkOpt=false, NetworkOptEntity=false, EnableProfiler=off, EnableTracy=off |
| `network_on` | RPC path | NetworkOpt=true (entity optional) |
| `render_preview` | client EarlyNative render | EnableVBPool=true, AngleBackend=auto |

Phase-2 DoD: **`defaults` + `minimal` green** on local machine with game. Other profiles optional.

### 6.5 Ordering relative to launch

```text
apply_profile(profile)
  → launch client smoke (Phase-1 contract)
  → assert inject/mod/world/stable
  → (optional) assert LG_CLIENT_CONFIG tokens match profile for keys under test
```

Config write is **out-of-process before launch**, not in-game UI clicking.

### 6.6 Risks / open implementation detail

| Risk | Mitigation |
|---|---|
| Opaque binary/encoded config format | Capture one real `modconfiguration_workshop-3444078585*` as fixture; reverse encode/decode in harness; or use game PersistentString helpers if available |
| `_dev` suffix / mod name aliases | Mirror native identity resolution (canonical + aliases) |
| EarlyNative options need restart | Always full process restart after write (no hot apply in Phase-2) |
| Server vs client config | Phase-2 client-only; server `modoverrides` is a later profile family |

---

## 7. Probe design (client)

`tests/plugin_client/probe_mod/`:

- `client_only_mod = true`  
- High priority so it runs; does not replace LuaJit2  
- Emit log tokens (primary):

| Token | When |
|---|---|
| `LG_CLIENT_INJECT_OK` | `GameInjector ~= nil` |
| `LG_CLIENT_INJECT_MISSING` | inject nil |
| `LG_CLIENT_MOD_LOADED` | probe GamePostInit (and/or detect LuaJit2 host) |
| `LG_CLIENT_PLUGINS_OK` | inject present + no hard fail signal from host if exposed |
| `LG_CLIENT_WORLD_READY` | SimPostInit / ThePlayer / InGamePlay as pinned in README |
| `LG_CLIENT_SIM_PAUSED` | optional if client pause API exists |
| `LG_CLIENT_CONFIG` | Phase-2: `key=value` lines for sampled options |
| `LG_CLIENT_STABLE` | written by **orchestrator** after hold |

Strict.lua: use `_G` / `rawget` / `setfenv` lessons from plugin MODROOT fix.

---

## 8. Success criteria

### Phase-1 (DoD)

| ID | Criterion | Proof |
|---|---|---|
| S-C1 | Client inject works | `LG_CLIENT_INJECT_OK` |
| S-C2 | Mod/plugins path healthy | `LG_CLIENT_MOD_LOADED` + `LG_CLIENT_PLUGINS_OK` |
| S-C3 | World ready + stable hold | `LG_CLIENT_WORLD_READY` + hold + `LG_CLIENT_STABLE` |
| S-C4 | Skip without game | no binary → SKIP |

### Phase-2 (DoD, after Phase-1)

| ID | Criterion | Proof |
|---|---|---|
| S-C5 | Config write applies | profile write path exists; probe `LG_CLIENT_CONFIG` matches overrides for sampled keys |
| S-C6 | Profile matrix | `defaults` + `minimal` both pass Phase-1 contract after apply_profile |

---

## 9. Implementation slices

| Slice | Deliverable | Gate |
|---|---|---|
| M-C0 | probe_mod + orchestrator skeleton + SKIP | unit: dry-run without game |
| M-C1 | Phase-1 green on local DST (P1a or P1b) | full contract |
| M-C2 | CTest + README | documented |
| M-C3 | **mod_config writer + profiles** | S-C5 |
| M-C4 | matrix `defaults` + `minimal` | S-C6 |

---

## 10. Spec self-review

| Check | Result |
|---|---|
| Phase-1 scope | Core inject only (C1) |
| Config mutation | Explicit Phase-2, not forgotten |
| Suite choice | In-house + tokens; no false UI framework |
| World strategy | P1a primary, P1b fallback |
| Placeholders | Config **codec** details deferred to M-C3 with fail-fast if format unknown |

---

## 11. Approval note

User additions incorporated:

- Phase-1 = goal **1** (core inject smoke).  
- **Follow-up must support mod configuration_options modification** (Phase-2 / M-C3–M-C4).
