# Client Host Smoke Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `--mode host`: single-process client-host smoke (no dedicated) with `LG_CLIENT_HOST_OK` + existing inject/world/hold contract.

**Architecture:** Extend `plugin_lc_probe` with a host bootstrap (env-gated) that mirrors `MainScreen:OnHostButton` (`TheNet:StartServer` + `LOAD_SLOT`). Orchestrator `run_p1_host()` launches only steam client, waits for host/world tokens, holds, kills. P1b path unchanged.

**Tech Stack:** Python 3 orchestrator, DST client Lua probe, existing L-C token oracle.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-03-client-host-smoke-design.md`
- No dedicated process in host mode (S-H1)
- No `stress_test_bot` / LAN join in host mode (H7)
- No caves / multi-shard (H5)
- Prefer existing save slot; empty-slot worldgen only if H-2 blocked (H6 / H-4)
- Tokens primary: `[lc_probe] TOKEN NAME body`
- Exit: 0 PASS, 1 FAIL, 2 SKIP; SKIP without game
- `force_enable_mods` separator is `;` (GameLua.cpp)
- Fail-fast if Injector missing when game present
- Phase-2 `--profile` must still work in host mode

## File map

| Path | Responsibility |
|---|---|
| `tests/plugin_client/probe_mod/modmain.lua` | Existing inject/config/world tokens + **host bootstrap when `LC_HOST_MODE=1`** |
| `tests/plugin_client/run_client_inject_smoke.py` | `run_p1_host()`, CLI `--mode host`, env `LC_HOST_SLOT` / `LC_HOST_MODE` |
| `tests/plugin_client/README.md` | Host runbook |
| `tests/CMakeLists.txt` | Optional second CTest `plugin_client_host_smoke` |

No new mod folder unless host logic makes probe too large; keep in probe with env gate (YAGNI).

---

### Task 1: Host bootstrap in probe (Lua)

**Files:**
- Modify: `tests/plugin_client/probe_mod/modmain.lua`
- Test: local client smoke after Task 2 (this task unit-check via syntax + dry launch tokens)

**Interfaces:**
- Consumes: env `LC_HOST_MODE` (string `"1"`), `LC_HOST_SLOT` (default `"1"`)
- Produces tokens: `LG_CLIENT_HOST_OK`, `LG_CLIENT_HOST_FAIL` (plus existing tokens)

- [ ] **Step 1: Add host helpers after existing token helpers**

In `modmain.lua`, after `emit_config_samples` / before `AddGamePostInit`, add:

```lua
local function env_flag(name)
    local v = rawget(_G, "os") and _G.os.getenv and _G.os.getenv(name)
    return v == "1" or v == "true" or v == "TRUE"
end

local function host_slot()
    local v = rawget(_G, "os") and _G.os.getenv and _G.os.getenv("LC_HOST_SLOT")
    local n = tonumber(v or "1") or 1
    if n < 1 then n = 1 end
    return n
end

local host_started = false

local function try_start_host()
    if host_started then
        return
    end
    if not env_flag("LC_HOST_MODE") then
        return
    end
    host_started = true

    local TheNet = rawget(_G, "TheNet")
    local ShardSaveGameIndex = rawget(_G, "ShardSaveGameIndex")
    local KnownModIndex = rawget(_G, "KnownModIndex")
    local StartNextInstance = rawget(_G, "StartNextInstance")
    local RESET_ACTION = rawget(_G, "RESET_ACTION")
    local DisableAllDLC = rawget(_G, "DisableAllDLC")

    if not TheNet or not ShardSaveGameIndex or not StartNextInstance or not RESET_ACTION then
        token("LG_CLIENT_HOST_FAIL", "missing_globals")
        return
    end

    local slot = host_slot()
    token("LG_CLIENT_HOST_BEGIN", "slot=" .. tostring(slot))

    local ok_inv, TheInventory = pcall(function() return rawget(_G, "TheInventory") end)
    if ok_inv and TheInventory then
        pcall(function()
            if TheInventory.HasSupportForOfflineSkins and TheInventory:HasSupportForOfflineSkins()
                and TheInventory.HasDownloadedInventory and not TheInventory:HasDownloadedInventory()
                and TheInventory.ForceLoadOfflineCache then
                TheInventory:ForceLoadOfflineCache()
            end
        end)
    end

    pcall(function()
        if ShardSaveGameIndex.LoadSlotEnabledServerMods then
            ShardSaveGameIndex:LoadSlotEnabledServerMods()
        end
        if KnownModIndex and KnownModIndex.Save then
            KnownModIndex:Save()
        end
    end)

    local serverdata = nil
    pcall(function()
        serverdata = ShardSaveGameIndex:GetSlotServerData(slot)
    end)

    local started = false
    local ok_start, ret = pcall(function()
        return TheNet:StartServer(false, slot, serverdata)
    end)
    started = ok_start and ret and true or false

    if not started then
        token("LG_CLIENT_HOST_FAIL", "StartServer_false")
        return
    end

    pcall(function()
        if DisableAllDLC then DisableAllDLC() end
    end)

    local ok_next, err = pcall(function()
        StartNextInstance({ reset_action = RESET_ACTION.LOAD_SLOT, save_slot = slot })
    end)
    if not ok_next then
        token("LG_CLIENT_HOST_FAIL", "StartNextInstance:" .. tostring(err))
        return
    end
    token("LG_CLIENT_HOST_STARTED", "slot=" .. tostring(slot))
end

local function emit_host_ok(reason)
    local TheNet = rawget(_G, "TheNet")
    local TheWorld = rawget(_G, "TheWorld")
    local hosted = false
    local mastersim = false
    pcall(function()
        if TheNet and TheNet.GetServerIsClientHosted then
            hosted = TheNet:GetServerIsClientHosted() and true or false
        end
    end)
    pcall(function()
        if TheWorld then mastersim = TheWorld.ismastersim and true or false end
    end)
    if hosted or mastersim then
        token("LG_CLIENT_HOST_OK", tostring(reason or "host") .. " hosted=" .. tostring(hosted) .. " mastersim=" .. tostring(mastersim))
    else
        token("LG_CLIENT_HOST_FAIL", "not_client_hosted reason=" .. tostring(reason))
    end
end
```

- [ ] **Step 2: Gate FE host start + world host assert**

1. In the first `AddGamePostInit` (inject tokens), keep inject/config as-is.
2. Add `AddClassPostConstruct("screens/redux/mainscreen", ...)` only when host mode:

```lua
if env_flag("LC_HOST_MODE") then
    AddClassPostConstruct("screens/redux/mainscreen", function(self)
        self.inst:DoTaskInTime(1, function()
            try_start_host()
        end)
    end)
end
```

3. In `emit_world_ready`, after emitting `LG_CLIENT_WORLD_READY`, if host mode call `emit_host_ok(reason)`.

4. **Spawn helper (host only):** copy stress bot Part 2 pattern (hook `ResumeRequestLoadComplete` → `SendSpawnRequestToServer`) behind `LC_HOST_MODE`, so empty character lobby still reaches world. Do **not** copy LAN search.

- [ ] **Step 3: Note os.getenv availability**

DST Lua often exposes `os.getenv`. If host mode never starts in smoke, orchestrator also passes a **mod config-free** signal by writing a tiny marker file the probe can read — **only if getenv fails in Task 2**. Prefer getenv first: orchestrator sets `LC_HOST_MODE=1` in client `env`.

- [ ] **Step 4: Commit**

```bash
git add tests/plugin_client/probe_mod/modmain.lua
git commit -m "feat(test): probe client-host StartServer bootstrap (LC_HOST_MODE)"
```

---

### Task 2: Orchestrator `--mode host`

**Files:**
- Modify: `tests/plugin_client/run_client_inject_smoke.py`
- Test: dry SKIP + local game host run

**Interfaces:**
- Consumes: probe tokens from Task 1
- Produces: `run_p1_host(game_dir, profile=None) -> int`

- [ ] **Step 1: Add timeouts and start_client_host**

Near existing `T_*` constants:

```python
T_HOST = float(os.environ.get("LC_T_HOST", "120"))
```

Change `start_client` to accept optional `extra_env: Optional[dict] = None` and merge into `env`.

Add:

```python
def start_client_host(game_dir: Path) -> LogProcess:
    force_mods = "plugin_lc_probe"  # no stress_test_bot
    extra = {
        "LC_HOST_MODE": "1",
        "LC_HOST_SLOT": os.environ.get("LC_HOST_SLOT", "1"),
        "AppVersionDevPatch": "1",
    }
    return start_client(game_dir, force_mods, extra_env=extra)
```

Update `start_client` signature:

```python
def start_client(game_dir: Path, force_mods: str, extra_env: Optional[dict] = None) -> LogProcess:
    ...
    env = os.environ.copy()
    env["AppVersionDevPatch"] = "1"
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})
```

P1b call site stays `start_client(game_dir, force_mods)` (no extra_env).

- [ ] **Step 2: Implement `run_p1_host`**

```python
def run_p1_host(game_dir: Path, profile: Optional[str] = None) -> int:
    if not ensure_injector(game_dir):
        return 1
    if not find_client_exe(game_dir):
        eprint("[lc] client binary missing")
        return 1

    install_probe(game_dir)
    # Do NOT install/enable stress_test_bot

    client = start_client_host(game_dir)
    try:
        if not wait_tokens(
            client,
            ("LG_CLIENT_MOD_LOADED", "LG_CLIENT_INJECT_OK", "LG_CLIENT_PLUGINS_OK"),
            T_INJECT,
        ):
            if "LG_CLIENT_INJECT_MISSING" in client.tokens:
                eprint("[lc] inject missing")
            return 1

        if profile and not verify_profile_tokens(client, profile):
            return 1

        # Host may emit HOST_STARTED before world; require HOST_OK or fail after T_HOST+T_WORLD window
        if not wait_tokens(client, ("LG_CLIENT_WORLD_READY",), T_WORLD):
            return 1

        if "LG_CLIENT_HOST_OK" not in client.tokens:
            # allow late emit shortly after world
            if not wait_tokens(client, ("LG_CLIENT_HOST_OK",), min(T_HOST, 60)):
                if "LG_CLIENT_HOST_FAIL" in client.tokens:
                    eprint(f"[lc] host fail: {client.token_bodies.get('LG_CLIENT_HOST_FAIL')}")
                else:
                    eprint("[lc] missing LG_CLIENT_HOST_OK")
                return 1

        print(f"[lc] holding stable for {T_HOLD}s...")
        hold_end = time.time() + T_HOLD
        while time.time() < hold_end:
            if not client.alive() or client.fatal:
                eprint("[lc] lost stability during hold")
                return 1
            time.sleep(0.5)

        print("[lc] LG_CLIENT_STABLE (orchestrator)")
        print("[lc] PASS client inject smoke (host)")
        return 0
    finally:
        client.stop()
```

- [ ] **Step 3: Wire CLI**

```python
parser.add_argument(
    "--mode",
    choices=("p1b", "host", "offline"),
    default=os.environ.get("LC_MODE", "p1b"),
    help="p1b=dedicated+LAN; host=client-host single process; offline=alias of host",
)
...
mode = args.mode
if mode == "offline":
    mode = "host"
if mode == "host":
    return run_p1_host(game_dir, profile=args.profile)
return run_p1b(game_dir, args.cluster, profile=args.profile)
```

- [ ] **Step 4: Dry SKIP without game**

Run:

```bash
set DST_GAME_DIR=
python tests/plugin_client/run_client_inject_smoke.py --mode host
```

Expected: prints SKIP, exit 0 under ctest mapping (exit 2 raw from main when required).

- [ ] **Step 5: Local green with game**

Prerequisite: offline save slot 1 (or `LC_HOST_SLOT`) already exists on the machine.

```bash
set LC_T_HOLD=15
set LC_HOST_SLOT=1
python tests/plugin_client/run_client_inject_smoke.py --mode host
```

Expected log excerpts:

```text
[lc] log-token LG_CLIENT_INJECT_OK
[lc] log-token LG_CLIENT_HOST_STARTED
[lc] log-token LG_CLIENT_WORLD_READY
[lc] log-token LG_CLIENT_HOST_OK
[lc] PASS client inject smoke (host)
```

If `LG_CLIENT_HOST_FAIL` with empty slot: document and implement Task 4 fallback before claiming done.

- [ ] **Step 6: Commit**

```bash
git add tests/plugin_client/run_client_inject_smoke.py
git commit -m "feat(test): --mode host client-host smoke without dedicated"
```

---

### Task 3: README + CTest target

**Files:**
- Modify: `tests/plugin_client/README.md`
- Modify: `tests/CMakeLists.txt`
- Optional: update plan/spec status after green

- [ ] **Step 1: README section**

Add:

```markdown
## Mode: host (client-hosted)

Single process: steam client hosts offline world (`TheNet:StartServer` + LOAD_SLOT).
No dedicated. No stress_test_bot.

```bash
set LC_T_HOLD=15
set LC_HOST_SLOT=1
python tests/plugin_client/run_client_inject_smoke.py --mode host

# with profile
python tests/plugin_client/run_client_inject_smoke.py --mode host --profile minimal
```

Tokens: existing `LG_CLIENT_*` plus `LG_CLIENT_HOST_OK` / `LG_CLIENT_HOST_FAIL`.
Requires a usable offline save slot (default 1) unless empty-slot fallback is implemented.
```

- [ ] **Step 2: CTest**

In `tests/CMakeLists.txt` after `plugin_client_inject_smoke`:

```cmake
add_test(NAME plugin_client_host_smoke
    COMMAND ${CMAKE_COMMAND} -E env
        REPO_ROOT=${CMAKE_SOURCE_DIR}
        DST_GAME_DIR=$ENV{DST_GAME_DIR}
        LC_MODE=host
        ${PYTHON_EXECUTABLE_NAME}
        ${CMAKE_CURRENT_SOURCE_DIR}/plugin_client/run_client_inject_smoke.py
        --mode host)
set_tests_properties(plugin_client_host_smoke PROPERTIES
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    TIMEOUT 900)
```

- [ ] **Step 3: Commit**

```bash
git add tests/plugin_client/README.md tests/CMakeLists.txt
git commit -m "docs(test): client-host mode runbook and CTest target"
```

---

### Task 4: Empty-slot fallback (only if Task 2 blocked)

**Files:**
- Modify: `tests/plugin_client/probe_mod/modmain.lua` host bootstrap

**Do not start this task if Task 2 is green on an existing slot.**

- [ ] **Step 1: Detect empty slot** via `ShardSaveGameIndex:IsSlotEmpty(slot)` (or equivalent)
- [ ] **Step 2: Minimal init** — mirror safe subset of host path: set default offline serverdata for slot, Save, then `StartServer` + `LOAD_SLOT` / worldgen reset action if required by vanilla empty-slot flow
- [ ] **Step 3: Re-run `--mode host` on empty slot** → PASS
- [ ] **Step 4: Commit** `fix(test): host smoke empty-slot fallback`

---

### Task 5: Closeout

- [ ] **Step 1: Mark design Implemented** in `docs/superpowers/specs/2026-08-03-client-host-smoke-design.md`
- [ ] **Step 2: Plan checklist all `[x]`** in this file
- [ ] **Step 3: Commit** `docs: close client-host smoke plan`

---

## Success criteria map

| ID | Task |
|---|---|
| S-H1 single client process | Task 2 `run_p1_host` |
| S-H2 inject/mod/plugins | Task 1+2 existing tokens |
| S-H3 `LG_CLIENT_HOST_OK` | Task 1+2 |
| S-H4 world + hold | Task 2 |
| S-H5 SKIP without game | Task 2 dry run |
| README/CTest | Task 3 |

## Spec coverage self-check

| Spec section | Plan task |
|---|---|
| H1–H7 decisions | Constraints + Tasks 1–2 |
| Single process / no dedicated | Task 2 |
| StartServer + LOAD_SLOT | Task 1 |
| No stress bot | Task 2 force_mods |
| Tokens incl. HOST_OK | Task 1 |
| CLI `--mode host` | Task 2 |
| Profiles still work | Task 2 profile branch |
| CTest second target | Task 3 |
| Empty slot H-4 | Task 4 conditional |
| No caves | Constraints / non-goals |

## Placeholder scan

No TBD/TODO left in required path. Empty-slot is explicitly conditional Task 4.

---

## Execution handoff

Plan complete and saved to `docs/superpowers/plans/2026-08-03-client-host-smoke.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — this session, executing-plans with checkpoints  

Which approach?
