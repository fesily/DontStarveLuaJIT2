# Design: Client Prediction-OFF Display Smoothing (Local Player)

> Status: Approved for planning (user 同意 2026-08-11)  
> Date: 2026-08-11  
> Related: `docs/investigation-movement-jitter-luajit.md`, `jitter_probe_dump.txt` analysis  

---

## 1. Problem

With **client Movement Prediction OFF** (`Profile:GetMovementPredictionEnabled()==false`):

- Local player has **no** locomotor / `SGwilson_client`.
- Input is `RPC.DirectWalking(dir)` only.
- Visual position comes solely from **server transform snapshots** (`Deserialize` → hard `SetPosition` / `Teleport`).
- Dump evidence (local self): Deserialize cadence ~**67ms** both ON and OFF; OFF post-snap residual ≈ **0** (hard align); ON residual ~**1.7** (prediction lead). Stair-step is **frozen between snaps**, not slower packets.

`sim.lagcomp` is **out of scope** (mastersim-only; user confirmed irrelevant).

---

## 2. Goals / Non-goals

### Goals

1. **Display-only** smoothing for the **local player** when prediction is OFF.
2. Reduce stair-step while walking; authority remains fully server-side.
3. Experimental, **opt-in** (`EnableClientSmooth` default **false**).
4. Fail-safe: disable on boat/teleport/pred ON; no C++ hooks for v1.

### Non-goals

- Not a replacement for full movement prediction (no `SGwilson_client`, no combat/action prediction).
- Not remote players, NPCs, or all entities (v1 = local player only).
- Not `sim.lagcomp` / mastersim FindEntities.
- Not C++ SetPosition/Deserialize interpolation for v1 (approach B deferred).
- Not forcing prediction ON by default (approach C rejected).

---

## 3. Scope (locked)

| Item | Choice |
|------|--------|
| Who | Local player only |
| When | Client + prediction OFF + feature option ON |
| How | Pure Lua display extrapolation (approach A) |
| Platform | All clients (Lua face; no Win-only requirement) |

---

## 4. Approaches considered

| | A Pure Lua wall-update extrapolate | B C++ hook Deserialize/SetPosition | C Force prediction ON |
|--|------------------------------------|------------------------------------|------------------------|
| Pros | Fast, no signatures, instant kill-switch | Precise snap detection | Zero new code |
| Cons | Slightly coarser snap detection | Maintenance, probe overlap | Does not fix OFF path |
| **Decision** | **Chosen** | Later if A insufficient | Rejected |

---

## 5. Architecture

```
[Input]  RemoteDirectWalking(dir) / RemoteStopWalking
            │
            ▼
[State]  last_dir, walking?, last_auth_pos, last_auth_time, display_pos
            │
            ├─ On auth snap (position jump from net / large Δ)
            │     re-anchor; optional short blend from display → auth
            │
            └─ OnWallUpdate(dt)   // render-rate
                  if not active: return
                  age = now - last_auth_time
                  if walking and age > 0:
                      extrap = last_auth + normalize(dir) * speed * age
                      clamp |extrap - last_auth| ≤ MAX_EXTRAP
                      optional blend toward extrap
                      Transform:SetPosition(display)  // client visual only
```

**Authority path unchanged:** server still simulates; client still sends only dirs; next snapshot remains SSOT and re-anchors.

---

## 6. Components

### 6.1 Plugin package `client.smooth` (`plugin_client_smooth`)

| Face | Role |
|------|------|
| Native EarlyNative | Optional: schema-only registrar for `EnableClientSmooth` if Host requires native schema; **no gameplay hooks** in v1 |
| Lua AfterModMain | `scripts/client_smooth.lua` — all behavior |

**Option:** `EnableClientSmooth` (bool, default `false`).

**Gates:**

- Package `when`: `has_luajit`, client (`is_client` / not dedicated)
- Runtime: `EnableClientSmooth`, `Profile:GetMovementPredictionEnabled()==false`, `inst==ThePlayer`, `locomotor==nil`

### 6.2 Runtime module (Lua)

Attach via `AddPlayerPostInit` (ThePlayer) and/or `AddComponentPostInit("playercontroller")`.

**State (per local player):**

| Field | Meaning |
|-------|---------|
| `last_dir_x/z` | last DirectWalking dir |
| `walking` | after DirectWalking until StopWalking |
| `auth_x/z`, `auth_t` | last authoritative pos + time |
| `disp_x/z` | last display write |
| `blend_t` | optional post-snap blend remaining |

**Hooks:**

1. Wrap `RemoteDirectWalking` → dir + walking=true  
2. Wrap `RemoteStopWalking` → walking=false  
3. Wall-rate update: piggyback `PlayerController:OnWallUpdate` if clean, else tiny wall-updating component  
4. Snap detection from Transform samples (§7)

### 6.3 Parent modinfo

Add `EnableClientSmooth` to `Mod/modinfo.lua` (default false; en/zh hover).

Register package in `Mod/plugins/init.lua`.

---

## 7. Snap detection (no C++)

Each WallUpdate:

1. Read `cur = Transform:GetWorldPosition()`.  
2. If we wrote display last frame and `|cur - expected_disp| < ε` (~1e-3), engine kept our write.  
3. If `|cur - auth| > SNAP_EPS` (0.05) and not explained by our extrap, **new authority**: set auth=cur, auth_t=now, optional blend.  
4. If `|cur - auth| > TELEPORT_EPS` (3.0): hard snap, clear blend, no extrap one frame.

Only this module calls `Transform:SetPosition` for the local player while active.

---

## 8. Parameters (v1 constants)

| Constant | Value | Notes |
|----------|-------|-------|
| `MAX_EXTRAP_DIST` | 1.2 | Cap display lead (units) |
| `SPEED` | `TUNING.WILSON_RUN_SPEED` or classified `runspeed` | |
| `SNAP_EPS` | 0.05 | Auth change |
| `TELEPORT_EPS` | 3.0 | Hard cut |
| `BLEND_TIME` | 0.08 s | Soft pull to auth |
| `DIR_DEADZONE` | 1e-3 | |

Y: never extrapolate (use auth y only).

---

## 9. Disable conditions

| Condition | Action |
|-----------|--------|
| Pred ON / locomotor present | disable; restore auth once |
| Option false | never start |
| Dedicated / mastersim | never start |
| `GetCurrentPlatform() ~= nil` | disable (v1 no boat) |
| Ghost | disable v1 |
| Optional: busy / hop tags | pause extrap |

---

## 10. Error handling

- Missing Profile/Transform: no-op.  
- Runtime option / pred toggle: re-check; clean disable.  
- Wall update in `pcall`; on error disable for session + one print.

---

## 11. Testing / verification

| Case | Expect |
|------|--------|
| OFF + option OFF | Stock pred-OFF |
| OFF + option ON, land walk | Smoother stairs; no fly-off |
| ON + option ON | Inactive; stock prediction |
| OFF + teleport | Hard snap |
| OFF + boat | Disabled |
| Leave world | No leak |

Optional: path/net via quiet jitter probe — OFF+smooth closer to ON than OFF raw.

---

## 12. Success criteria

1. Pred OFF + option ON: reduced stair-step vs option OFF.  
2. Pred ON unchanged.  
3. No crash; boat/teleport safe.  
4. Default option OFF — no change for users who do not enable.

---

## 13. Resolved for v1

| Item | Resolution |
|------|------------|
| Scope | Local player only |
| Approach | A — pure Lua |
| Default | `EnableClientSmooth` false |
| Boat / ghost | Disable |
| Native logic | None (schema-only if packaging needs it) |

## 14. Follow-ups (out of scope)

- Remote player smoothing  
- C++ residual blend (B)  
- Anim/facing prediction  
- RTT-scaled extrap horizon  
