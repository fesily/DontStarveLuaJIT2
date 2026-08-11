# Investigation: Client Movement Jitter after LuaJIT

> Status: Phase-1 root-cause investigation (no fix yet)
> Date: 2026-08-11
> Binary reference: `dontstarve_steam` macOS 32-bit (full symbols)
> Target symptom: after LuaJIT VM replacement, local player jitters while moving
> User suspicion: animation / render path

---

## 0. Locked Scope (user-confirmed 2026-08-11)

| Item | Verdict |
|------|---------|
| `plugin_sim_lagcomp` | **Out of scope.** User confirmed on/off same; mastersim-only, never on client visual path. |
| **Client Movement Prediction** | **OFF** — this is what user means by「不开延迟补偿」(`Profile:GetMovementPredictionEnabled()==false` / options movementprediction). |
| Local motor / `SGwilson_client` | **Not active.** `EnableMovementPrediction(false)` removes locomotor, `ClearStateGraph()`, `entity:EnableMovementPrediction(false)`. |
| Client movement I/O | `PlayerController:DoDirectWalking` → `RemoteDirectWalking` → `RPC.DirectWalking(dir.x, dir.z)` only (directions, not positions). |
| Visual position source | **Server-authoritative snapshots only** via `cTransformComponent::Deserialize` → `SetPosition` / `Physics::Teleport` (no local prediction history). |
| Injector C hooks on Transform/Physics/AnimState | **None found** |
| Always-on change post-LuaJIT | `core.vm` replaces Lua API + changes GC semantics; optional FrameGC / TargetRenderFPS / network.rpc |

**Implication:** With prediction OFF, every visible step of the local player is a **network-applied transform snap** (plus whatever engine interpolation exists on physics/render). Stock Lua51 may hide micro-jitter; LuaJIT frame/GC/tick timing can make the same snaps look stuttery. Anim is **server SG replicated**, not client `run_loop` prediction.
---

## 1. Prediction-OFF Visual Position Pipeline (macOS symbols)

```
[CLIENT INPUT — no local motor]
  PlayerController:OnUpdate
    → DoDirectWalking
      → locomotor == nil
      → RemoteDirectWalking(dir.x, dir.z)
      → SendRPCToServer(RPC.DirectWalking, x, z)   -- directions only

[SERVER]
  OnRemoteDirectWalking → server locomotor RunInDirection
  physics integrate → serialize transform dirty bits

[CLIENT NET APPLY — sole visual pos source]
  cTransformComponent::Deserialize(BitStream)
    → CheckTransformationPredictionHistory  // pPredictionHistory==null → returns 0
    → Physics::Teleport(serverPos) or SetPosition(serverPos)   // HARD SNAP path
    → optional pTransformHistory::Write (interp buffer if allocated)
    → UpdateTransform → UpdateWorldPosition → SceneGraphNode::SetTransform

[RENDER SNAPSHOT]
  AnimNode::DoCacheForRender @ 0xc259c
    → TDataCacheAnimNode copies Matrix4 from SceneGraph (frozen)
  TDataCacheAnimNode::DrawCacheRender @ 0xc156a
    → draws CACHED matrix; anim frames from server-replicated AnimState

[NOT IN PATH when prediction OFF]
  locomotor / SGwilson_client / SetMotorVel / GetPredictionPosition
  nPredictionEnabled state machine / PostPhysicsWallUpdate history append
  sim.lagcomp FindEntities apply/restore
```

### 1.1 Why prediction OFF is maximally sensitive to LuaJIT timing

1. **No local continuous motion.** ON path integrates `SetMotorVel` every sim tick locally → smooth even if net is late. OFF path only moves when a snapshot lands.
2. **Deserialize applies absolute pos** via `Teleport`/`SetPosition` when prediction history is empty (always empty if never enabled).
3. **`TeleportRespectingInterpolation` @ 0x67d4c** exists (velocity-aware COM adjust) but net apply path used in Deserialize is the plain `Teleport`/`SetPosition` branch when `CheckTransformationPredictionHistory` returns 0 — i.e. **hard snaps**, not client-side prediction reconcile.
4. **Render freezes matrix** at `DoCacheForRender`. If sim ticks (and thus Deserialize) cluster/hitch due to GC, display shows stair-steps.
5. **Anim is server-driven** (no client run SG). Walk cycle phase comes from replicated state; pos snaps + anim frame advance can look like "animation jitter" even when root cause is pos snapshot cadence.

### 1.1 Key native symbols (macOS)

| Symbol | Addr | Role |
|--------|------|------|
| `cTransformComponent::SetPosition` | `0x7f753` | Writes local pos + `UpdateTransform` |
| `cTransformComponent::UpdateTransform` | `0x7f2b0` | Rebuild mats → `UpdateWorldPosition` → `SceneGraphNode::SetTransform` |
| `cEntity::UpdateWorldPosition` | `0xcf826` | Copies transform provider pos into entity worldPos cache |
| `cPhysicsComponent::SetLocalMotorVel` | `0x67fe0` | Motor; **zeros vel if `nPredictionEnabled >= 2`** |
| `cPhysicsComponent::Teleport` | `0x67c50` | Rigid body COM + `SetPosition` (hard snap) |
| `cTransformComponent::EnableMovementPrediction` | `0x80f32` | Alloc/free `pPredictionHistory`, state 0/1 |
| `cTransformComponent::PostPhysicsWallUpdate` | `0x811f2` | Append history; ACTIVE→WAITING on buffer overflow |
| `cTransformComponent::CheckTransformationPredictionHistory` | `0x8072e` | Server pos convergence state machine |
| `cTransformComponent::GetPredictionPosition` | `0x80ee4` | Tail of `pPredictionHistory` |
| `cTransformComponent::Deserialize` | (via SetPosition path) | Network pos apply + history truncate |
| `cEntity::SetIsPredictingMovement` | `0xd1d36` | Flag only (`bIsPredictingMovement`) |
| `AnimNode::DoCacheForRender` | `0xc259c` | **Render matrix snapshot** |
| `TDataCacheAnimNode::DrawCacheRender` | `0xc156a` | Draws from snapshot matrix |

### 1.2 Why animation/render can look like "jitter" even if physics is smooth

Render does **not** read live `flWorldPos` every pixel frame. It:

1. Snapshots transform matrix into `TDataCacheAnimNode` at `DoCacheForRender`.
2. Draws later from that cache (`DrawCacheRender`).

If **sim tick / render snapshot timing** drifts (LuaJIT GC hitch, FrameGC on `ProfilerPop("Update")`, TargetRenderFPS/netbook frame-time patch), you get:

- position advances on sim ticks in uneven wall-time steps, **or**
- render reuses a stale matrix for multiple display frames then jumps,

which presents as character "stutter/jitter". Facing (`facingMode==8` mirror) and run anim (`AnimState:PlayAnimation(run_loop)`) can amplify it if anim frame and pos snap are phase-misaligned.

---

## 2. Lua Script Path (stock DST)

### 2.1 Prediction ON (default client)

```
player_common.EnableMovementPrediction(true)
  → AddComponent("locomotor") + SetStateGraph("SGwilson_client")
  → entity:EnableMovementPrediction(true)   -- native nPredictionEnabled=1
  → RPC.SetMovementPredictionEnabled(true)

PlayerController:OnUpdate(dt)
  → DoPredictWalking (client report via GetPredictionPosition)
  → else DoDragWalking / DoDirectWalking
       → locomotor:RunInDirection → PushEvent("locomote")
SGwilson_client run_start/run
  → locomotor:RunForward → Physics:SetMotorVel(speed,0,0)
  → AnimState:PlayAnimation(run_pre / run_loop)
```

### 2.2 Prediction OFF (highly jitter-sensitive)

```
EnableMovementPrediction(false)
  → remove locomotor, ClearStateGraph
  → entity:EnableMovementPrediction(false)
  → playercontroller.locomotor = nil

PlayerController:OnUpdate
  → DoDirectWalking: CanLocomote() false
  → RemoteDirectWalking(dir.x, dir.z)   -- RPC.DirectWalking only
  → NO local Physics:SetMotorVel
  → visual position = network Deserialize snaps only
```

This mode is pure "server authority + client interpolate/snap". Any change in:

- network tick rate / snapshot arrival jitter
- RPC/serialize channel ordering (`plugin_network_rpc`)
- sim vs render frame pacing

shows up as position jitter. Anim will also desync because there is **no client SG run loop** driving walk cycles from local motor — anim comes from server state graph replication.

### 2.3 Key script files

| File | Symbols |
|------|---------|
| `dst-scripts/scripts/prefabs/player_common.lua` | `EnableMovementPrediction` (~877) |
| `dst-scripts/scripts/components/playercontroller.lua` | `OnUpdate`, `DoPredictWalking` (~4003), `DoDirectWalking` (~4306), `RemoteDirectWalking` (~3903), rubber-band `Physics:Teleport` (~4090) |
| `dst-scripts/scripts/components/locomotor.lua` | `RunInDirection`, `SetMotorSpeed`, `OnUpdate` |
| `dst-scripts/scripts/stategraphs/SGwilson_client.lua` | `locomote` handler, `run_start`/`run`, `SetIsPredictingMovement`, `FlattenMovementPrediction` |
| `dst-scripts/scripts/screens/redux/optionsscreen.lua` | UI toggle prediction |
| `dst-scripts/scripts/prefabs/player_classified.lua` | `pausepredictionframes` → `cancelmovementprediction` |

Project `Mod/` does **not** monkey-patch these (except lagcomp mastersim FindEntities).

---

## 3. Injector Delta after LuaJIT (what actually changed)

### 3.1 Absent (negative findings — good)

- No C hooks on `SetPosition` / `UpdateTransform` / `SetLocalMotorVel` / `Teleport`
- No hooks on `EnableMovementPrediction` / prediction state machine
- No hooks on `AnimState` / `AnimNode` / `DrawCacheRender`
- No wallupdate / physics-step reordering
- No `GetTickTime` / `FRAMES` C intercept

### 3.2 Present (suspect ranking for client jitter, lagcomp OFF)

| Rank | Component | Mechanism | Why it can jitter |
|------|-----------|-----------|-------------------|
| **1 HIGH** | `core.vm` always-on | Full Lua API replace; `lua_gc` hooked; jit_gen swallows non-COUNT GC | Changes GC timing vs stock Lua51 → uneven sim frame cost |
| **2 HIGH** | `debug.profiler` FrameGC / FullGC | `ProfilerPush/Pop("Update")` → leftover budget `TryDoGC`; `lj_gc_fullgc_external` may defer fullgc | Hitch on sim Update boundary; pos integrates in uneven wall-time |
| **3 MED** | `fps.render` TargetRenderFPS | Patches notebook-mode frame-time immediates; exports `g_frame_time_s` | Render/sim pace desync; FrameGC budget wrong |
| **4 MED** | `network.rpc` + `network.entity` | Serialize orderingChannel by networkid hash | Snapshot apply order for nearby ents (less for local player) |
| **5 LOW** | `network.tick` | Binary patch client up/down tick constants | Only if API actually called (not auto in init registry) |
| **6 LOW** | `render.vbpool` / ANGLE | GL buffer pool / renderer | Frame hitch only, not logical pos |
| N/A | `sim.lagcomp` | entity+0x1f0 apply/restore | Mastersim only; OFF |

Load order (`Mod/plugins/init.lua`): profiler(20) → network.rpc/entity(40) → fps.render(50) → lagcomp/netsim(60) → jit.runtime(70).

---

## 4. Working Hypotheses (prediction OFF locked — test in order)

### H1 — Sim-frame hitch from LuaJIT GC / FrameGC *(primary)*
Uneven `Update` wall-time → Deserialize/pos snaps land in irregular clusters → stair-step motion. Stock Lua51 GC smoother → less visible.
**Falsify:** FrameGC+FullGC defer OFF; stock Lua51 vs LuaJIT with E14/E15 + E1/E2 cadence histogram.

### H2 — Render snapshot phase drift (`DoCacheForRender` vs net apply)
Pos snaps at sim; matrix frozen for N display frames; looks like anim/pos stutter.
**Falsify:** log E1 vs E11 same wall window; disable TargetRenderFPS/netbook patch.

### H3 — Network snapshot cadence / apply order (LuaJIT timing side-effect)
`RPC.DirectWalking` out + transform snapshots in; any change in tick processing or `network.rpc` channel order changes snap spacing.
**Falsify:** E9 Deserialize rate vs S9 RemoteDirectWalking rate; toggle NetworkOptEntity.

### H4 — Server DirectWalking path jitter (listen/dedicated)
Server motor integrate + serialize rate; client only mirrors. Not LuaJIT-client-only if dedicated host is stock.
**Falsify:** client LuaJIT + dedicated stock server still jitters → client-side; both stock smooth → host path.

### H5 — Anim replication phase vs hard pos snaps *(presentation / user suspicion)*
No client run SG; walk anim from server. Pos hard snaps + anim frame advance look like "动画抖".
**Falsify:** after H1–H3; E11 matrix Δ vs AnimState frame index; if pos smooth but anim pops → anim path.

### Dropped (not in prediction-OFF path)
- Prediction state thrash / SetLocalMotorVel gate
- Client GetPredictionPosition / SGwilson_client run_loop
- sim.lagcomp

---

## 5. Engine Log Insertion Points (prediction-OFF priority)

Tag: `wall_ns`, local-player `guid`, `x,z`, op name. macOS addrs → Win x64 via string/sig later.

### Tier A — must (pos truth on net-apply path)

| # | Function (macOS) | Addr | Log | Why |
|---|------------------|------|-----|-----|
| E1 | `cTransformComponent::SetPosition` | `0x7f753` | old/new xyz, retaddr | Every logical pos write |
| E2 | `cPhysicsComponent::Teleport` | `0x67c50` | xyz | Hard snap from Deserialize |
| E9 | `cTransformComponent::Deserialize` pos branch | (caller→E1/E2) | dirty bits, Teleport vs SetPosition | **Sole visual pos source** |
| E4 | `UpdateTransform` end | `0x7f2b0` | flWorldPos | Post-apply world pos |

### Tier B — render (user suspicion)

| # | Function | Addr | Log | Why |
|---|----------|------|-----|-----|
| E11 | `AnimNode::DoCacheForRender` | `0xc259c` | matrix translation, facingMode | Render snapshot pos |
| E12 | `DrawCacheRender` entry | `0xc156a` | cached matrix translation | Stale draw detection |
| E13 | `SceneGraphNode::SetTransform` | from UpdateTransform | mat translation | Graph feed |

### Tier C — injector timing (LuaJIT delta)

| # | Location | Log | Why |
|---|----------|-----|-----|
| E14 | `ProfilerPush("Update")` | wall start | Sim frame start |
| E15 | `ProfilerPop` + TryDoGC | elapsed, budget, gc_steps, fullgc_phase | Hitch source |
| E16 | `lj_gc_fullgc_external` | deferred? | FullGC policy |
| E17 | `g_frame_time_s` | value | FrameGC/render budget |

### Tier D — sanity only (should be silent when pred OFF)

| # | Function | Expect |
|---|----------|--------|
| E6 | `EnableMovementPrediction` | only at spawn/options; must stay false |
| E3 / E7 / E8 / E10 | Motor / PostPhysics / PredCheck / GetPredPos | **no calls** for local player if truly OFF |

Format: `[JITTER][ENG] t_wall=%lld guid=%u op=%s x=%.4f z=%.4f extra=...`  
Ops: `SetPos`, `Teleport`, `Deserialize`, `WorldPos`, `CacheRender`, `DrawCache`, `SimUpdateBegin`, `SimUpdateEndGC`.

---

## 6. Scripts Log Insertion Points (prediction-OFF priority)

Client-only temporary probe; gate `DS_JITTER_PROBE=1` / mod config.

### Tier S1 — mode lock (must prove OFF)

| # | Site | Log |
|---|------|-----|
| S1 | `EnableMovementPrediction` | enable flag (expect false path) |
| S2 | spawn / options | `Profile:GetMovementPredictionEnabled()`, `locomotor==nil`, `sg==nil` |
| S3 | once per second assert | `assert(ThePlayer.components.locomotor == nil)` while probing |

### Tier S2 — client input (what we send)

| # | Site | Log |
|---|------|-----|
| S5 | `PlayerController:OnUpdate` | dt, tick, `has_locomotor` (must N), busy |
| S7 | `DoDirectWalking` | dir.x/z |
| S9 | `RemoteDirectWalking` | dir + tick + wall time |
| S9b | `RemoteStopWalking` | tick |

### Tier S3 — visual sample (what we see)

| # | Site | Log |
|---|------|-----|
| S11 | periodic every tick on ThePlayer | `Transform:GetWorldPosition()`, `|Δpos|`, dt_wall |
| S13 | if AnimState API available | current anim bank/name/time |
| S18 | camera/player follow optional | follow target pos vs entity pos |

### Tier S4 — server (only if listen-server same process)

| # | Site | Log |
|---|------|-----|
| S19 | `OnRemoteDirectWalking` | dir, server pos after integrate |
| S20 | not DoPredictWalking rubber-band | N/A when client pred OFF (server uses direct path) |

```lua
local function JLog(tag, fmt, ...)
    print(string.format("[JITTER][LUA][t=%d][%s] "..fmt, GetTick(), tag, ...))
end

-- client-only
if TheNet:IsDedicated() then return end

AddPlayerPostInit(function(inst)
    if inst ~= ThePlayer then return end
    local last_x, last_z, last_wall
    inst:DoPeriodicTask(0, function()
        if not inst:IsValid() then return end
        local x,y,z = inst.Transform:GetWorldPosition()
        local loco = inst.components.locomotor
        local wall = GetTime()
        local d = last_x and math.sqrt((x-last_x)^2+(z-last_z)^2) or 0
        local dt = last_wall and (wall-last_wall) or 0
        JLog("pos", "xyz=%.3f,%.3f,%.3f d=%.4f dt=%.4f loco=%s sg=%s",
            x,y,z,d,dt, loco and "Y" or "N", inst.sg and inst.sg.currentstate and inst.sg.currentstate.name or "nil")
        last_x, last_z, last_wall = x, z, wall
    end)
end)

AddComponentPostInit("playercontroller", function(self)
    local old = self.RemoteDirectWalking
    function self:RemoteDirectWalking(x, z, ...)
        if self.inst == ThePlayer then
            JLog("rpc", "DirectWalking dir=%.3f,%.3f loco=%s", x, z,
                self.locomotor and "Y" or "N")
        end
        return old(self, x, z, ...)
    end
end)
```

## 7. Reproduce Matrix (prediction OFF fixed)

| Run | VM | FrameGC | FullGC defer | TargetFPS | Pred | Expect |
|-----|----|---------|--------------|-----------|------|--------|
| A | stock Lua51 | off | off | default | **OFF** | baseline |
| B | LuaJIT | off | off | default | **OFF** | if jitters → core.vm / net apply timing |
| C | LuaJIT | on | on | default | **OFF** | if worse → H1 FrameGC |
| D | LuaJIT | off | off | patched | **OFF** | if worse → H2 fps/render |
| E | LuaJIT | off | off | default | **ON** | control: if smooth → confirms OFF-path sensitivity |
| F | B + E1/E2/E9/E11/E14-15 logs | | | | **OFF** | cadence evidence |

Capture 5–10s continuous WASD; plot client `x(t),z(t)`, `|Δpos|` per tick, wall Δt between Deserializes.

Optional: same client vs **dedicated stock server** to split H4.

---

## 8. Win x64 Address Port (confirmed 2026-08-11)

| Symbol | Win x64 | Notes |
|--------|---------|-------|
| `EnableMovementPrediction` | `0x140091460` | `pHistory+0x198`, `nPred+0x1a4` |
| `PostPhysicsWallUpdate` | `0x14008f3a0` | string `Locomotor: Waiting...` |
| `Deserialize` | `0x1400917e0` | error string `"position"` |
| `SetPosition` | `0x140090c10` | local pos `+0x38/0x3c/0x40` |
| `Physics::Teleport` | `0x1400a24a0` | calls SetPosition via transform `+0x28` |
| `GetPredictionPosition` | `0x14008e730` | history tail |
| `entity::EnableMovementPrediction` | `0x140108be0` | flag `+0x1bc`, transform via `+0x1e0` |
| serverPos cache | transform `+0x44` | Deserialize writes here first |
| flLocalPos | transform `+0x38` | SetPosition target |
| pPredictionHistory | `+0x198` | null when pred OFF |
| nPredictionEnabled | `+0x1a4` | 0 when OFF |

Probe plugin: `plugin_debug_jitterprobe` (`debug.jitterprobe`), option `EnableJitterProbe` (default false).

**Enable:**
1. Build / deploy `plugin_debug_jitterprobe.dll` into mod `plugins/`.
2. Set option `EnableJitterProbe=true` (save / mod config / env-cmd cascade if wired).
3. Client with **Movement Prediction OFF**, join world; logs:
   - engine: `[JITTER][ENG] op=Deserialize|SetPos|Teleport|EnablePred ...`
   - lua: `[JITTER][LUA][t=N][pos|rpc|mode] ...`
4. Expect when pred OFF: `loco=N`, many `Deserialize`/`SetPos`/`Teleport`, `EnablePred enable=0` only at spawn; no continuous local motor.

Hooks: SetPosition / Teleport / Deserialize / EnableMovementPrediction. Lua: RemoteDirectWalking + per-tick pos.

---

## 9. Conclusions

1. **`sim.lagcomp` irrelevant** (user-confirmed; mastersim-only).
2. **Repro = client Movement Prediction OFF** — pure `RPC.DirectWalking` + server snapshot snaps; no local motor/SG.
3. **No injector rewrites Transform/Physics/Anim.** Suspect is **timing**: LuaJIT GC/FrameGC/frame pacing changing snap cadence / render freeze phase.
4. **Anim/render is presentation:** `DoCacheForRender` freezes matrix; server anim + hard pos snaps can look like "动画抖" when root is pos cadence.
5. **First probes:** S2/S3 (prove loco nil) + S9/S11 + E1/E2/E9 + E11 + E14/E15; matrix A/B/C/E.

Next: implement those probes on Win x64, run A–E, lock one hypothesis before any fix.

## 10. Mitigation experiment (2026-08-11)

- Package: `client.smooth` / option `EnableClientSmooth` (default **false**, opt-in)
- Spec: `docs/superpowers/specs/2026-08-11-client-pred-off-display-smooth-design.md`
- Plan: `docs/superpowers/plans/2026-08-11-client-pred-off-display-smooth.md`
- Implementation: `Mod/plugins/plugin_client_smooth/` (`scripts/client_smooth.lua`)
- Scope: **display-only** local-player extrapolation when movement prediction is **OFF**; does **not** replace full prediction (`SGwilson_client` / locomotor).
- Human playtest still required for cases A–F (pred OFF/ON, option on/off, teleport, boat, leave world) before treating stair-step as fixed.

