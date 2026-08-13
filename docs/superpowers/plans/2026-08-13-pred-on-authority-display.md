# Pred-ON Authority vs Display Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the pred-OFF `client.anim` product path so display/anim use stock `EnableMovementPrediction(true)` and combat stays server-authoritative.

**Architecture:** Klei already splits coordinates: predicted transform + client SG/loco for display/anim; server sim for hits; `local_a0` skips network AnimTime/hash/mode. This plan deletes our pred-OFF replacement (Deserialize `BL` force, hardware watch, Lua `PlayAnimation` drive). No new reconcile math. No display extrapolation.

**Tech Stack:** C++23 plugin MODULE, Lua 5.1 Host, CMake Ninja Multi-Config, DST client.

**Spec:** `docs/superpowers/specs/2026-08-13-pred-on-authority-display-design.md`

## Global Constraints

- P1: Combat / hitbox = server position only.
- P4: Display extrapolation forbidden (`client.smooth` must not return).
- P5: No second Transform / render offset.
- P6: Pred-OFF anim path abandoned; git history kept; delete the code.
- P7: History miss → engine `Teleport`; no blend radius this plan.
- P8: First delivery is delete + measure. No new native reconcile.
- Do not treat jitter-probe Lua `time_back` as fail (loop wrap + `GetCurrentAnimationTime` fmod).
- Skip formatters / project-wide test suites inside subagent tasks; one verify at the end of each task as specified.
- `Mod/` is the workshop junction; edit `Mod/plugins/...` and `src/DontStarveInjector/plugins/...` together when both exist.

## File map

| Path | Role after this plan |
|------|----------------------|
| `Mod/plugins/init.lua` | Drop `load_package("plugin_client_anim")` |
| `src/DontStarveInjector/CMakeLists.txt` | Drop `plugin_client_anim` add_subdirectory + Gum foreach |
| `Mod/modinfo.lua` | Drop `EnableClientAnimOwn` widget |
| `src/DontStarveInjector/plugins/plugin_client_anim/` | **Delete** |
| `Mod/plugins/plugin_client_anim/` | **Delete** (Lua + staged DLL) |
| `Mod/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua` | Comments only: probe, not anim own |
| `src/DontStarveInjector/plugins/plugin_debug_jitterprobe/` | Same comment / stale export note |
| `docs/superpowers/specs/2026-08-13-plugin-option-export-design.md` | Drop `EnableClientAnimOwn` bake-table row |

---

### Task 1: Unwire registry, CMake, and option widget

**Files:**
- Modify: `Mod/plugins/init.lua:111-123`
- Modify: `src/DontStarveInjector/CMakeLists.txt:328-341`
- Modify: `Mod/modinfo.lua:450-471`
- Modify: `docs/superpowers/specs/2026-08-13-plugin-option-export-design.md:267-268`

**Interfaces:**
- Consumes: Host `load_package` / `ds_add_dynamic_plugin` (unchanged)
- Produces: Registry and build graph with no `client.anim` / `EnableClientAnimOwn`

- [ ] **Step 1: Failing check that the option and registry still exist**

From repo root:

```bash
python -c "from pathlib import Path
init=Path('Mod/plugins/init.lua').read_text(encoding='utf-8')
mod=Path('Mod/modinfo.lua').read_text(encoding='utf-8')
cm=Path('src/DontStarveInjector/CMakeLists.txt').read_text(encoding='utf-8')
assert 'plugin_client_anim' in init
assert 'EnableClientAnimOwn' in mod
assert 'plugin_client_anim' in cm
print('PRE: still wired')"
```

Expected: `PRE: still wired`

- [ ] **Step 2: Remove the registry line**

In `Mod/plugins/init.lua` delete only:

```lua
    load_package("plugin_client_anim"),
```

Leave `plugin_debug_jitterprobe` immediately above and `plugin_debug_profiler` immediately below.

- [ ] **Step 3: Remove CMake target**

In `src/DontStarveInjector/CMakeLists.txt`:

- Delete `add_subdirectory(plugins/plugin_client_anim)`
- Delete `plugin_client_anim` from the `foreach(_ds_gum_plugin IN ITEMS ...)` list

Do not touch other Gum plugins.

- [ ] **Step 4: Remove the Mods UI row**

In `Mod/modinfo.lua` delete the entire table entry:

```lua
    {
        name = "EnableClientAnimOwn",
        ...
    }
```

Keep the preceding `EnableJitterProbe` entry and the closing `}` of `configuration_options`. Trailing comma on `EnableJitterProbe` must stay valid Lua.

- [ ] **Step 5: Drop the bake-table row in the option-export spec**

In `docs/superpowers/specs/2026-08-13-plugin-option-export-design.md` delete:

```markdown
| `EnableClientAnimOwn` | `plugin_client_anim` |
```

Leave `EnableJitterProbe` row.

- [ ] **Step 6: Re-run the wiring check (must fail the old asserts / pass inverted)**

```bash
python -c "from pathlib import Path
init=Path('Mod/plugins/init.lua').read_text(encoding='utf-8')
mod=Path('Mod/modinfo.lua').read_text(encoding='utf-8')
cm=Path('src/DontStarveInjector/CMakeLists.txt').read_text(encoding='utf-8')
assert 'plugin_client_anim' not in init, init
assert 'EnableClientAnimOwn' not in mod
assert 'add_subdirectory(plugins/plugin_client_anim)' not in cm
assert 'plugin_client_anim' not in cm
print('PASS: unwired')"
```

Expected: `PASS: unwired`

- [ ] **Step 7: Commit**

```bash
git add Mod/plugins/init.lua src/DontStarveInjector/CMakeLists.txt Mod/modinfo.lua docs/superpowers/specs/2026-08-13-plugin-option-export-design.md
git commit -m "chore: unwire client.anim from registry, CMake, and Mods UI"
```

---

### Task 2: Delete plugin_client_anim trees

**Files:**
- Delete: `src/DontStarveInjector/plugins/plugin_client_anim/` (all: `plugin_client_anim.cpp`, `ClientAnimHooks.cpp`, `ClientAnimHooks.hpp`, `ClientAnimOptionKeys.hpp`, `CMakeLists.txt`, `modinfo.lua`, `modmain.lua`, `scripts/client_anim.lua`)
- Delete: `Mod/plugins/plugin_client_anim/` (Lua copies + `plugin_client_anim.dll` if present)

**Interfaces:**
- Consumes: Task 1 (CMake no longer `add_subdirectory` this dir)
- Produces: No `client.anim` MODULE, no `DS_LUAJIT_client_anim_*` exports

- [ ] **Step 1: Confirm Task 1 landed (CMake must not reference the directory)**

```bash
python -c "from pathlib import Path
cm=Path('src/DontStarveInjector/CMakeLists.txt').read_text(encoding='utf-8')
assert 'plugin_client_anim' not in cm
print('PASS: cmake clean')"
```

Expected: `PASS: cmake clean`

- [ ] **Step 2: Delete both package directories**

```bash
git rm -r src/DontStarveInjector/plugins/plugin_client_anim
git rm -r Mod/plugins/plugin_client_anim
```

If `Mod/plugins/plugin_client_anim/plugin_client_anim.dll` is untracked, delete it from disk as well (`Remove-Item` / `rm`) so the workshop folder does not keep loading a stale DLL.

- [ ] **Step 3: Repo-wide leftover check**

```bash
python -c "from pathlib import Path
needles=('plugin_client_anim','EnableClientAnimOwn','DS_LUAJIT_client_anim','kEnableClientAnimOwn')
# allow this plan + pred-on spec + git history mentions in docs that describe abandonment
allow=('docs/superpowers/plans/2026-08-13-pred-on-authority-display.md',
       'docs/superpowers/specs/2026-08-13-pred-on-authority-display-design.md')
root=Path('.')
bad=[]
for p in list(root.rglob('*')):
    if not p.is_file():
        continue
    s=str(p).replace('\\\\','/')
    if any(s.replace('\\\\','/').endswith(a) or a in s.replace('\\\\','/') for a in allow):
        continue
    if '.git' in p.parts or 'builds' in p.parts:
        continue
    try:
        t=p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        continue
    for n in needles:
        if n in t:
            bad.append(f'{p}: {n}')
if bad:
    print('LEFTOVER')
    print('\\n'.join(bad))
    raise SystemExit(1)
print('PASS: no product leftovers')"
```

Expected: `PASS: no product leftovers`

If `jitter_probe.lua` or `JitterProbeHooks.cpp` still mention `client.anim`, that is Task 3 — do not expand Task 2 to edit them; the check should exclude those two files **or** Task 2 check should list them as known and Task 3 must clear them. **Required:** if the script fails only on jitterprobe comments, record the paths and continue to Task 3 (do not revert the delete).

- [ ] **Step 4: Identity gate still green**

```bash
python tools/check_plugin_package_identity.py --source-root .
```

Expected: exit 0 (no `plugin_client_anim` identity pair required).

- [ ] **Step 5: Commit**

```bash
git add -A src/DontStarveInjector/plugins/plugin_client_anim Mod/plugins/plugin_client_anim
git commit -m "chore: delete plugin_client_anim (pred-OFF anim path abandoned)"
```

---

### Task 3: Jitter probe is measurement-only

**Files:**
- Modify: `Mod/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua:1-12`
- Modify: `Mod/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua:44-46`
- Modify: `Mod/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua:223-225`
- Modify: `src/DontStarveInjector/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua` (same lines if it is a separate copy — keep identical)
- Modify: `src/DontStarveInjector/plugins/plugin_debug_jitterprobe/JitterProbeHooks.cpp:684-687`

**Interfaces:**
- Consumes: Probe still binds `track_entity` itself; no `DS_LUAJIT_client_anim_*`
- Produces: Comments/logs that do not point at a deleted plugin

- [ ] **Step 1: Replace header comment**

In both `jitter_probe.lua` copies, change the block at the top from “anim own → client.anim” to:

```lua
-- Pred-OFF local run/idle ownership was removed (spec 2026-08-13 pred-ON).
-- This file is measurement only. Lua time_back on looping anims is wrap+fmod,
-- not a network AnimTime fault.
```

- [ ] **Step 2: Replace load prints**

```lua
print("[JITTER][LUA] probe on (authority + frame/render)")
```

and at EOF:

```lua
print("[JITTER][LUA] loaded — probe only")
```

- [ ] **Step 3: Stale C export comment**

In `JitterProbeHooks.cpp` around `DS_LUAJIT_jitter_probe_set_local_player_entity`:

```cpp
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_local_player_entity(void *entity) {
    // No-op. Local-player filter is Lua track_entity / native track pointer.
    (void)entity;
}
```

Do not restore a bind implementation.

- [ ] **Step 4: Leftover check including jitterprobe**

```bash
python -c "from pathlib import Path
needles=('plugin_client_anim','DS_LUAJIT_client_anim','EnableClientAnimOwn')
allow=('docs/superpowers/plans/2026-08-13-pred-on-authority-display.md',
       'docs/superpowers/specs/2026-08-13-pred-on-authority-display-design.md',
       'docs/superpowers/specs/2026-08-13-plugin-option-export-design.md')
bad=[]
for p in Path('.').rglob('*'):
    if not p.is_file() or '.git' in p.parts or 'builds' in p.parts:
        continue
    s=str(p).replace('\\\\','/')
    if any(a in s for a in allow):
        continue
    try:
        t=p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        continue
    for n in needles:
        if n in t:
            bad.append(f'{p}: {n}')
if bad:
    raise SystemExit('LEFTOVER\\n'+'\\n'.join(bad))
print('PASS: probe decoupled')"
```

Expected: `PASS: probe decoupled`

- [ ] **Step 5: Commit**

```bash
git add Mod/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua src/DontStarveInjector/plugins/plugin_debug_jitterprobe/scripts/jitter_probe.lua src/DontStarveInjector/plugins/plugin_debug_jitterprobe/JitterProbeHooks.cpp
git commit -m "chore: detach jitter probe comments from deleted client.anim"
```

---

### Task 4: Pred-ON measurement (no new code)

**Files:**
- None required. Optional one-line pointer in `docs/investigation-movement-jitter-luajit.md` only if the operator wants the protocol in-tree; **do not** add reconcile code.

**Interfaces:**
- Consumes: Stock DST prediction; optional `EnableJitterProbe`
- Produces: Operator verdict (pass/fail visual) recorded in the PR/commit message or a follow-up note — not a new feature

- [ ] **Step 1: Build Injector + remaining plugins**

```bash
cmake --build builds/ninja-multi-vcpkg --config Debug --target Injector -j 16
```

Expected: success. Must **not** compile `plugin_client_anim`.

- [ ] **Step 2: Confirm staged plugins folder has no client.anim DLL**

```bash
python -c "from pathlib import Path
hits=list(Path('Mod/plugins').rglob('*client_anim*'))+list(Path('builds/ninja-multi-vcpkg/src/DontStarveInjector/Debug/plugins').rglob('*client_anim*'))
print(hits)
assert not hits
print('PASS: no staged client_anim')"
```

Expected: `PASS: no staged client_anim`

- [ ] **Step 3: In-game protocol (operator)**

1. Settings: **Movement Prediction ON**.
2. Do **not** expect `[client.anim] loaded` in `client_log.txt`.
3. Same walk on **game VM** and **JIT**.
4. Pass: mid-walk not worse than game VM; no new recoil vs stock pred ON.
5. If probe on: `EnablePred` / transform Deserialize may appear; **ignore** looping `time_back`.
6. Pred OFF smoke: game still runs; anim/pos are stock replica (unaided).

- [ ] **Step 4: Commit only if Step 2 needed a leftover delete**

If Step 2 found a stray DLL, delete it and:

```bash
git add -A Mod/plugins
git commit -m "chore: remove leftover plugin_client_anim staging artifacts"
```

If nothing to commit, skip.

---

## Spec coverage

| Spec | Task |
|------|------|
| P1 server combat | No code; pred ON stock |
| P2 pred ON display/anim | Task 4 protocol |
| P3 server does not chase | No code |
| P4 no extrapolation | No `client.smooth` restore (Tasks 1–3 delete only) |
| P5 no second transform | No new files |
| P6 abandon pred-OFF anim | Tasks 1–3 |
| P7 no blend radius | Task 4 forbids new math |
| P8 delete + measure | Tasks 1–4 |
| Verification §7 | Task 4 |
| Option-export bake row | Task 1 |

## Placeholder / consistency review

- No TBD. Exact paths and commands.
- `EnableClientAnimOwn` removed from UI and option-export table in Task 1 before directory delete in Task 2.
- Jitterprobe leftover mentions cleared in Task 3 after Task 2 delete.
