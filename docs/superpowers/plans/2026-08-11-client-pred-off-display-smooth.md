# Client Pred-OFF Display Smooth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Opt-in local-player display-only position extrapolation when client movement prediction is OFF, reducing stair-step without changing server authority.

**Architecture:** Pure Lua package `plugin_client_smooth` (`client.smooth`). Wrap `RemoteDirectWalking` / `RemoteStopWalking`, run WallUpdate loop on local player to `Transform:SetPosition` between network snaps. No C++ gameplay hooks. Default option `EnableClientSmooth=false`.

**Tech Stack:** DST Lua (client), existing PluginHost dual-face package pattern, parent `Mod/modinfo.lua` configuration_options.

## Global Constraints

- Spec: `docs/superpowers/specs/2026-08-11-client-pred-off-display-smooth-design.md`
- Scope: **local player only**; not remotes/NPCs; not `sim.lagcomp`
- Active only when: client + `EnableClientSmooth` + prediction OFF + `locomotor == nil`
- Disable: boat (`GetCurrentPlatform() ~= nil`), ghost, pred ON, option OFF, dedicated/mastersim
- Constants: `MAX_EXTRAP_DIST=1.2`, `SNAP_EPS=0.05`, `TELEPORT_EPS=3.0`, `BLEND_TIME=0.08`, no Y extrap
- YAGNI: no native logic hooks; no RTT scaling; no anim prediction
- No per-frame print in hot path

## File map

| Path | Responsibility |
|------|----------------|
| `Mod/modinfo.lua` | User option `EnableClientSmooth` |
| `Mod/plugins/plugin_client_smooth/modinfo.lua` | Package identity + `when` + `all_of` |
| `Mod/plugins/plugin_client_smooth/modmain.lua` | `modimport("scripts/client_smooth")` |
| `Mod/plugins/plugin_client_smooth/scripts/client_smooth.lua` | All runtime logic |
| `Mod/plugins/init.lua` | Register package in load list |
| `src/DontStarveInjector/plugins/plugin_client_smooth/*` | Optional mirror of package for identity/source tree (Lua-only OK if identity gate skips stems without native) |

**Note:** Follow `plugin_network_sim` / `plugin_debug_jitterprobe` dual-face layout under both `Mod/plugins/` and `src/DontStarveInjector/plugins/` for packaging consistency. **No C++ required** for v1 logic; if identity gate expects native for dual-face stems, either (a) do **not** add stem to `DUAL_FACE` list, or (b) add minimal schema-only `plugin_client_smooth.cpp` like other packages. Prefer **(a)** unless repo convention forces dual native for every package.

---

### Task 1: Option + package skeleton

**Files:**
- Modify: `Mod/modinfo.lua` (append option near client experimental options)
- Create: `Mod/plugins/plugin_client_smooth/modinfo.lua`
- Create: `Mod/plugins/plugin_client_smooth/modmain.lua`
- Create: `Mod/plugins/plugin_client_smooth/scripts/client_smooth.lua` (stub print only)
- Modify: `Mod/plugins/init.lua` (add `load_package("plugin_client_smooth")`)
- Mirror under `src/DontStarveInjector/plugins/plugin_client_smooth/` same Lua files

**Interfaces:**
- Produces: option key string `"EnableClientSmooth"`; plugin_id `"client.smooth"`; package loadable by Host

- [ ] **Step 1: Add parent modinfo option**

In `Mod/modinfo.lua`, before closing `configuration_options` (`}` before `--restart_required`), add:

```lua
    {
        name = "EnableClientSmooth",
        label = translate({ en = "Client Smooth (Pred OFF)", zh = "客户端平滑(关预测)" }),
        hover = translate({
            en = "Display-only extrapolation for local player when movement prediction is OFF (experimental).",
            zh = "关闭移动预测时，仅对本地玩家做显示层外推（实验性）。",
        }),
        options = toggle,  -- same as EnableNetSim if `toggle` exists; else false/true pair
        default = false,
    },
```

If `toggle` is not in scope at that line, use explicit false/true options like `EnableJitterProbe`.

- [ ] **Step 2: Create package modinfo**

`Mod/plugins/plugin_client_smooth/modinfo.lua`:

```lua
name = "Client Smooth"
description = "Local-player display smooth when movement prediction is OFF."
author = "fesil"
version = "1.0.0"
api_version = 10
dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true
client_only_mod = true
server_only_mod = false
all_clients_require_mod = false
priority = 55
plugin_id = "client.smooth"
phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "EnableClientSmooth" } }

when = function(ctx)
    if not ctx or not ctx.has_luajit then
        return false
    end
    if ctx.is_client ~= nil then
        return ctx.is_client
    end
    if TheNet and TheNet.IsDedicated then
        return not TheNet:IsDedicated()
    end
    return true
end
```

- [ ] **Step 3: modmain + stub script**

`modmain.lua`:
```lua
modimport("scripts/client_smooth")
```

`scripts/client_smooth.lua` stub:
```lua
if TheNet and TheNet:IsDedicated() then return end
print("[client.smooth] package loaded (stub)")
```

- [ ] **Step 4: Register in init.lua**

Add after jitterprobe (or near other client packages):

```lua
load_package("plugin_client_smooth"),
```

- [ ] **Step 5: Mirror files under `src/DontStarveInjector/plugins/plugin_client_smooth/`**

Copy the same three Lua files for source-of-truth packaging.

- [ ] **Step 6: Smoke — Host should list package**

Run game or existing plugin package load tests if any. Expected: with option false, package may register but `all_of` disables load; with option true on client, stub print appears once.

- [ ] **Step 7: Commit**

```bash
git add Mod/modinfo.lua Mod/plugins/init.lua Mod/plugins/plugin_client_smooth src/DontStarveInjector/plugins/plugin_client_smooth
git commit -m "feat(client.smooth): package skeleton + EnableClientSmooth option"
```

---

### Task 2: Core smooth runtime (gates + wall loop)

**Files:**
- Modify: `Mod/plugins/plugin_client_smooth/scripts/client_smooth.lua` (full implementation)
- Mirror: `src/DontStarveInjector/plugins/plugin_client_smooth/scripts/client_smooth.lua`

**Interfaces:**
- Consumes: `GetModConfigData("EnableClientSmooth")` or gate via Host already applied (if package only loads when option on, still re-check Profile)
- Produces: wraps RemoteDirectWalking/StopWalking; wall-rate SetPosition while active

- [ ] **Step 1: Replace stub with full module**

Implement `scripts/client_smooth.lua` as a single file with these pieces (complete logic, not placeholders):

```lua
-- client_smooth.lua
-- Display-only extrap for local player when movement prediction is OFF.
if TheNet and TheNet:IsDedicated() then return end

local MAX_EXTRAP_DIST = 1.2
local SNAP_EPS = 0.05
local TELEPORT_EPS = 3.0
local BLEND_TIME = 0.08
local DIR_DEADZONE = 1e-3
local EPSILON_DISP = 1e-3

local function pred_on()
    return Profile and Profile.GetMovementPredictionEnabled and Profile:GetMovementPredictionEnabled()
end

local function get_speed(inst)
    if inst.player_classified and inst.player_classified.runspeed then
        local v = inst.player_classified.runspeed:value()
        if type(v) == "number" and v > 0 then return v end
    end
    return (TUNING and TUNING.WILSON_RUN_SPEED) or 6
end

local function should_run(inst)
    if inst ~= ThePlayer then return false end
    if pred_on() then return false end
    if inst.components and inst.components.locomotor ~= nil then return false end
    if inst:HasTag("playerghost") then return false end
    if inst.GetCurrentPlatform and inst:GetCurrentPlatform() ~= nil then return false end
    return true
end

local function attach(inst)
    local st = {
        walking = false,
        dir_x = 0, dir_z = 0,
        auth_x = 0, auth_y = 0, auth_z = 0, auth_t = 0,
        disp_x = 0, disp_z = 0,
        wrote = false,
        blend_t = 0,
        blend_from_x = 0, blend_from_z = 0,
        active = false,
    }

    local function reanchor(x, y, z, now, blend)
        if blend and st.wrote then
            st.blend_from_x, st.blend_from_z = st.disp_x, st.disp_z
            st.blend_t = BLEND_TIME
        else
            st.blend_t = 0
        end
        st.auth_x, st.auth_y, st.auth_z = x, y, z
        st.auth_t = now
        st.disp_x, st.disp_z = x, z
    end

    local function hard_restore()
        if st.active then
            inst.Transform:SetPosition(st.auth_x, st.auth_y, st.auth_z)
        end
        st.wrote = false
        st.walking = false
        st.active = false
    end

    -- init auth from current
    do
        local x, y, z = inst.Transform:GetWorldPosition()
        local now = GetTime()
        reanchor(x, y, z, now, false)
    end

    local old_remote = nil
    local old_stop = nil
    local pc = inst.components.playercontroller
    if pc then
        old_remote = pc.RemoteDirectWalking
        old_stop = pc.RemoteStopWalking
        if type(old_remote) == "function" then
            function pc:RemoteDirectWalking(x, z, ...)
                if self.inst == inst then
                    st.dir_x, st.dir_z = x or 0, z or 0
                    st.walking = (math.abs(st.dir_x) + math.abs(st.dir_z)) > DIR_DEADZONE
                end
                return old_remote(self, x, z, ...)
            end
        end
        if type(old_stop) == "function" then
            function pc:RemoteStopWalking(...)
                if self.inst == inst then
                    st.walking = false
                end
                return old_stop(self, ...)
            end
        end
        -- Wall path: wrap OnWallUpdate
        local old_wall = pc.OnWallUpdate
        function pc:OnWallUpdate(dt, ...)
            if old_wall then old_wall(self, dt, ...) end
            if self.inst ~= inst then return end
            local ok, err = pcall(function()
                if not should_run(inst) then
                    if st.active then hard_restore() end
                    return
                end
                st.active = true
                local now = GetTime()
                local cx, cy, cz = inst.Transform:GetWorldPosition()

                -- teleport / large external move
                local d_auth = math.sqrt((cx - st.auth_x)^2 + (cz - st.auth_z)^2)
                if d_auth > TELEPORT_EPS then
                    reanchor(cx, cy, cz, now, false)
                    st.wrote = false
                    return
                end

                -- snap detection
                local expected_x, expected_z = st.disp_x, st.disp_z
                local d_exp = math.sqrt((cx - expected_x)^2 + (cz - expected_z)^2)
                if st.wrote and d_exp < EPSILON_DISP then
                    -- still our display
                elseif d_auth > SNAP_EPS then
                    reanchor(cx, cy, cz, now, true)
                end

                if not st.walking then
                    -- hold auth (optionally finish blend)
                    if st.blend_t > 0 then
                        st.blend_t = math.max(0, st.blend_t - dt)
                        local u = 1 - (st.blend_t / BLEND_TIME)
                        if u < 0 then u = 0 elseif u > 1 then u = 1 end
                        local dx = st.auth_x + (st.blend_from_x - st.auth_x) * (1 - u) -- wait: blend FROM display TO auth
                        -- correct: lerp(blend_from, auth, u)
                        dx = st.blend_from_x + (st.auth_x - st.blend_from_x) * u
                        local dz = st.blend_from_z + (st.auth_z - st.blend_from_z) * u
                        inst.Transform:SetPosition(dx, st.auth_y, dz)
                        st.disp_x, st.disp_z = dx, dz
                        st.wrote = true
                    end
                    return
                end

                local age = now - st.auth_t
                if age < 0 then age = 0 end
                local len = math.sqrt(st.dir_x * st.dir_x + st.dir_z * st.dir_z)
                if len < DIR_DEADZONE then return end
                local nx, nz = st.dir_x / len, st.dir_z / len
                local speed = get_speed(inst)
                local dist = speed * age
                if dist > MAX_EXTRAP_DIST then dist = MAX_EXTRAP_DIST end
                local ex = st.auth_x + nx * dist
                local ez = st.auth_z + nz * dist
                if st.blend_t > 0 then
                    st.blend_t = math.max(0, st.blend_t - dt)
                    local u = 1 - (st.blend_t / BLEND_TIME)
                    if u < 0 then u = 0 elseif u > 1 then u = 1 end
                    -- blend_from toward extrap endpoint
                    ex = st.blend_from_x + (ex - st.blend_from_x) * u
                    ez = st.blend_from_z + (ez - st.blend_from_z) * u
                end
                inst.Transform:SetPosition(ex, st.auth_y, ez)
                st.disp_x, st.disp_z = ex, ez
                st.wrote = true
            end)
            if not ok then
                print("[client.smooth] error: " .. tostring(err))
                hard_restore()
            end
        end
    end

    inst:ListenForEvent("enablemovementprediction", function(_, enable)
        if enable then hard_restore() end
    end)
    inst:ListenForEvent("playerdeactivated", function()
        hard_restore()
    end)
end

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then return end
        if not should_run(inst) and pred_on() then
            -- still attach wrappers so toggling pred OFF mid-session works
        end
        attach(inst)
    end)
end)

print("[client.smooth] scripts loaded")
```

**Implementer note:** Fix blend math carefully as in comments (lerp from `blend_from` to target). Prefer keeping the file clean; the block above is the intended behavior. If `OnWallUpdate` is not called without `handler`, also `StartWallUpdatingComponent` via a tiny component — verify in playtest; if wall never runs, add:

```lua
inst:AddComponent("updatelooper") -- only if exists on player; else custom
```

DST players already have playercontroller wall updating on client when controls attached; local player with handler should get `OnWallUpdate`. Confirm during Task 3 playtest; if not, add fallback component with `OnWallUpdate` only.

- [ ] **Step 2: Sync mirror under src/DontStarveInjector/plugins/plugin_client_smooth/**

- [ ] **Step 3: Commit**

```bash
git add Mod/plugins/plugin_client_smooth src/DontStarveInjector/plugins/plugin_client_smooth
git commit -m "feat(client.smooth): display extrap wall loop for pred-OFF local player"
```

---

### Task 3: Playtest matrix + fix fallout

**Files:**
- Possibly tweak constants / wall fallback in `client_smooth.lua` only

**Interfaces:** none new

- [ ] **Step 1: Playtest checklist**

| Case | Action | Pass |
|------|--------|------|
| A | Pred OFF, option OFF, walk | Stock jitter (baseline) |
| B | Pred OFF, option ON, walk flat land | Visibly smoother; no fly |
| C | Pred ON, option ON | Identical to stock pred ON |
| D | B + wormhole/teleport | Hard snap, no stretch |
| E | B + boat | Module disabled (no extrap) |
| F | Toggle pred OFF→ON mid-walk | Clean handoff, no stuck offset |

- [ ] **Step 2: If wall update never fires**

Add fallback: custom component

```lua
local ClientSmoothDriver = Class(function(self, inst)
    self.inst = inst
    inst:StartWallUpdatingComponent(self)
end)
function ClientSmoothDriver:OnWallUpdate(dt)
    -- call same step function used by wrap
end
```

Only if Step 1 proves OnWallUpdate wrap is dead.

- [ ] **Step 3: If SetPosition fights engine every frame**

Reduce write rate or only write when `|extrap - cur| > 1e-3`; re-verify residual behavior against dump understanding (auth freezes between des).

- [ ] **Step 4: Commit fixes if any**

```bash
git add Mod/plugins/plugin_client_smooth/scripts/client_smooth.lua
git commit -m "fix(client.smooth): playtest fallout"
```

---

### Task 4: Docs touch-up

**Files:**
- Modify: `docs/investigation-movement-jitter-luajit.md` — short "Mitigation experiment" pointing to package + option
- Optionally one line in `docs/plugin-system.md` inventory table if that file lists all packages

- [ ] **Step 1: Add mitigation note**

```markdown
## Mitigation experiment (2026-08-11)

- Package: `client.smooth` / `EnableClientSmooth` (default false)
- Spec: `docs/superpowers/specs/2026-08-11-client-pred-off-display-smooth-design.md`
- Display-only local extrap when pred OFF; does not replace full prediction.
```

- [ ] **Step 2: Commit**

```bash
git add docs/investigation-movement-jitter-luajit.md docs/plugin-system.md
git commit -m "docs: client.smooth mitigation pointer"
```

---

## Spec coverage self-check

| Spec section | Task |
|--------------|------|
| §2 Goals opt-in local display | T1 option + T2 gates |
| §5 Architecture wall extrap | T2 |
| §6 Package + modinfo | T1 |
| §7 Snap detection | T2 reanchor / SNAP_EPS / TELEPORT_EPS |
| §8 Constants | T2 header constants |
| §9 Disable boat/ghost/pred | T2 `should_run` / hard_restore |
| §10 pcall | T2 wall pcall |
| §11 Testing | T3 matrix |
| §12 Success | T3 |
| No C++ gameplay | All tasks Lua-only |

## Placeholder scan

No TBD steps; wall fallback is conditional with concrete code.

## Type/name consistency

- Option: `EnableClientSmooth`
- plugin_id: `client.smooth`
- stem: `plugin_client_smooth`
- script: `client_smooth.lua`
