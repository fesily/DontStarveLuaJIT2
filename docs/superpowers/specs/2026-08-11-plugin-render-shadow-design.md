# plugin_render_shadow Design — DontStarveLuaJIT2

**Date:** 2026-08-11  
**Status:** Draft for review  
**Scope:** Native **AfterModMain** plugin that drives **engine DynamicShadow** geometry from a world sun model (tier A), with a **reserved** silhouette-batch path (tier B) and an explicit non-goal of classical shadow maps (tier C research only).
**Related:** Ghidra RE on `dontstarve_steam` (`GenerateVB` @ `0x70fa0`, `PopulateQuad` @ `0x711f2`, `TDataCacheShadowRenderer::DrawCacheRender` @ `0x71900`); workshop mod Terminus Light (`3761111244`); `docs/anim-draw-batching-design.md`; `docs/plugin-system.md`; `plugin_render_vbpool` / `plugin_render_angle`.

---

## 1. Decisions (locked)

| # | Decision | Choice |
|---|---|---|
| D1 | Plugin identity | Dynamic module `plugin_render_shadow.dll`, id **`render.shadow`**, phase **AfterModMain**, Windows client only. |
| D2 | v1 delivery | **Tier A only** — sun-driven engine splat shadows via hook of `ShadowManagerComponent::GenerateVB` / sun dir fed into `PopulateQuad`. |
| D3 | Tier B | **Designed + reserved** in this spec (interfaces, data contracts, acceptance). **Not implemented in v1.** |
| D4 | Tier C | **Research / non-goal for product path.** Classical depth shadow maps rejected for DST 2.5D; optional future “caster mask RT” is out of v1 and not scheduled. |
| D5 | Visual target | **Soft ellipse under entities**, length driven by day phase — **not** character silhouette (that is B). v1 does **not** claim per-shadow opacity recolour. |
| D6 | Relation to Terminus Light | **No hard dependency.** A coexists with workshop silhouette mods. No auto-disable of stock splat when a Lua silhouette mod is present (v1). |
| D7 | Config ownership | Plugin registers its own option schema (`ShadowSunDrive`, `ShadowLengthBoost`). **No** new fields on `GameJitModConfig` struct. ConfigView is SSOT. |
| D8 | Gum | Import Frida Gum **only** from Injector re-exports (same as other gum plugins). Never second static Gum. |
| D9 | CRT / ABI | Same multi-config CRT as Injector; no STL across DLL boundary in Host APIs. Internal C++ OK inside plugin. |
| D10 | Success | Client inject + FE smoke: with option on, engine shadows lean with time-of-day (not camera heading); with option off, stock path; hook installed **before first in-world GenerateVB**. |

---

## 2. Problem statement

### 2.1 Engine shadows are camera-aligned ellipses

From Ghidra (`ShadowManagerComponent::GenerateVB`):

```text
cam = cSimulation::GetCurrentCameraInfo(...)
angle = (cam.heading + C1) * C2
dir = (cos(angle), sin(angle))   // GLOBAL for all shadows
for each DynamicShadowComponent (enabled, parent not culled):
  PopulateQuad(verts, entity.xz, sizeXY, dir)
CreateVB → one Draw in pass==2 (splat.ksh)
```

Lua surface is only:

```text
Entity:AddDynamicShadow()
  :SetSize(x, y)
  :Enable(bool)
ShadowManager:SetTexture / GenerateStaticShadows
```

There is **no** `SetRotation`, per-shadow colour, or sun API.

### 2.2 Terminus Light’s solution is heavy

Workshop mod clones AnimState entities, hooks global AnimState methods, runs per-shadow tasks. Correct silhouette, expensive and conflict-prone.

### 2.3 Classical shadow maps do not fit

- No engine shadow-map pass/symbols.
- Geometry is billboard anim, not stable 3D meshes.
- `HWRenderTarget` has depth slots; `WallStencilBuffer` / `LightBuffer` are **not** sun projection.
- Full CSM/PCF would re-draw anim from sun view with wrong billboard facing — high cost, poor fit.

### 2.4 Opportunity

Tier A reuses the **already-batched** splat path (1 dynamic VB / frame). Changing **global dir + optional size scale** gives day-driven shadows without extra entities.

---

## 3. Goals / non-goals

### Goals (v1)

1. Install sticky hooks (AfterModMain `load`) that replace camera-derived shadow direction with a **world sun yaw** derived from the same day model family as Terminus Light (phase + `timeinphase`).
2. Scale effective shadow **length** by day progress and `ShadowLengthBoost`. Seasonal/precip alpha and shader edits are **out of v1**.
3. Config off = stock behaviour (no visual change).
4. Degrade cleanly: missing signature / non-client / dedicated → plugin `can_load` false or load no-op.
5. Document tier B contracts so a later plan can implement silhouette batch without redesigning A.

### Non-goals (v1)

- Character silhouette / AnimState clone replacement (tier B implementation).
- Shadow maps, caster-mask RT, PCF, custom `.ksh` authoring pipeline (tier C).
- Replacing or forking Terminus Light.
- Linux/macOS product path (Windows client first; same pattern later if gum stage exists).
- Cross-DLL C++ Host APIs; plugin marketplace; hot-unload of sticky hooks.
- Network-syncing sun state (client render-only; each client reads `TheWorld.state` / engine world state as today).

---

## 4. Tier definitions

### 4.1 Tier A — Sun-driven engine splat (v1 implement)

| Item | Spec |
|---|---|
| Hook targets | **`ShadowManagerComponent::GenerateVB`** as sole A entry. Reimplement body via original `PopulateQuad` + `CreateVB` (D locked in §8). |
| Sun model | World yaw from day/dusk/night(+fullmoon) progress; shared constants with documented defaults matching Terminus Light geometry intent (max/min leg), not a line-by-line port. |
| Per-entity | Still uses `DynamicShadow` sizeXY + enable; A multiplies the **length axis** (the axis stock treats as stretch under `dir`) by global `length_scale`. |
| Draw path | Unchanged: `TDataCacheShadowRenderer::DrawCacheRender` pass 2, `splat.ksh`. |
| Cost | ~same as stock (still one VB). |

### 4.2 Tier B — Silhouette batch (design reserve only)

| Item | Spec |
|---|---|
| Purpose | Replace “clone AnimState entity” with CPU transform of `sBuild` verts into ground plane + few draws. |
| Data | Reuse analysis from `docs/anim-draw-batching-design.md` (24B BatchVertex, `TDataCacheAnimNode` snapshot). |
| Integration | **Same plugin** (`render.shadow`), future feature flag — not a second plugin id. |
| Flag | **Do not register** `ShadowSilhouetteBatch` until B ships (no dead options). |
| Acceptance (future) | No extra entity per caster; player silhouette tracks sun yaw; FE cost << Terminus Light under dense entities. |

### 4.3 Tier C — Caster-mask / shadow map (explicit non-goal)

Documented only so future work does not rediscover dead ends:

- True depth shadow maps: rejected for product.
- Low-res caster mask + ground project: possible research after B; not in this delivery train.

---

## 5. Architecture

```text
┌──────────────────────────── Game.exe ────────────────────────────┐
│ ShadowManagerComponent::GenerateVB / PopulateQuad / DrawCache…  │
└─────────────────────────────┬────────────────────────────────────┘
                              │ Gum hook (Injector-exported gum)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ plugin_render_shadow.dll   id=render.shadow                      │
│  AfterModMain load:                                              │
│    resolve symbols (signature / pattern / relocated ranges)      │
│    install GenerateVB hook if ShadowSunDrive                     │
│  SunState:                                                       │
│    read phase/progress from cSimulation / world (S0 pins fields) │
│    compute yaw + length_scale                                    │
│  Hooked GenerateVB:                                              │
│    same component list walk as stock                             │
│    dir = sun_dir instead of camera_dir                           │
│    optional size_y *= length_scale                               │
│    PopulateQuad → CreateVB (call originals)                      │
└─────────────────────────────────────────────────────────────────┘
         │ schema / ConfigView
         ▼
┌─────────────────────┐
│ Injector PluginHost │  (no reverse dep on shadow impl)
└─────────────────────┘
```

### 5.1 Responsibility split

| Component | Owns |
|---|---|
| `plugin_render_shadow` | Schema, sun model, GenerateVB hook, logging, can_load |
| Injector L0 | Gum export, DynamicPluginLoader, ConfigView merge |
| Game engine | DynamicShadow components, splat draw, StaticShadow VB |
| `plugin_render_vbpool` | Independent. A does not require VBPool; no link-time dependency. |
| `plugin_render_angle` | GL backend only; no API dep |

### 5.2 Load order

```text
Phase timing:
  Inject → load_all(DLL maps) → EarlyNative (angle/vbpool/…)
        → Lua / modmain → AfterModMain
            render.shadow load()  // resolve + optional hook install
        → enter world → first GenerateVB  // MUST already be hooked if enabled

Priority within AfterModMain (suggested): ~50 (no hard deps on other AfterModMain plugins).
Not EarlyNative: no IAT/GL-init race; GenerateVB is first used in-world, far after modmain.
```

### 5.2.1 Why AfterModMain (not EarlyNative)

| Constraint | render.angle / vbpool | render.shadow |
|---|---|---|
| Must win before first GL/IAT use | Yes | No |
| Target first used | Process init | In-world shadow pass |
| Config | Early ConfigView | AfterModMain can use mod options / ConfigView already resolved |

**Hard requirement:** if `ShadowSunDrive`, hook is live **before the first in-world `GenerateVB`**. AfterModMain runs at modmain completion — well before enter-world. Installing later (e.g. console) is allowed but out of v1 Host phase model.

EarlyNative remains a **fallback** only if S0 proves symbol/reloc infrastructure is unavailable after Lua open (no current evidence).

### 5.3 Symbol resolution strategy

1. Prefer existing relocation / signature infrastructure used by other render hooks (function name patterns on non-stripped refs where available; Windows x64 ranges via project’s function-range pipeline).
2. Anchor strings: `"shaders/splat.ksh"`, `ShadowRenderer`, `GenerateStaticShadows` for validation.
3. If resolve fails → log error, **do not crash inject**; plugin stays loaded with feature disabled.

Exact x64 RVAs are **not** locked in this doc (32-bit Ghidra evidence is structural). Implementation plan must include a calibration step on the shipping client binary.

---

## 6. Configuration (schema)

Registered in `ds_plugin_module_init`. **Only keys that work in v1:**

| Key | Type | Default | Behaviour |
|---|---|---|---|
| `ShadowSunDrive` | Bool | `false` | Master enable for tier A |
| `ShadowLengthBoost` | Float | `1.0` (clamp 0.5–2.0) | Multiplies day `length_scale` |

Do **not** register silhouette, seasonal, or alpha keys in v1.

Modinfo projection: dual-face package optional later; v1 may be native-only AfterModMain with schema keys mirrored when packaging.

---

## 7. Sun model (A)

### 7.1 Inputs

Read the same conceptual state Lua uses (concrete native offsets pinned in S0):

- `phase`: day / dusk / night
- `timeinphase` or equivalent progress ∈ [0,1]
- `isfullmoon` (night: sun-drive only on full moon; else passthrough/hide)

Season / precipitation: **out of v1**.

**Source of truth in native:** map from `cSimulation` / world entity components already used by game UI/time — implementation plan must pin the concrete offsets after 64-bit RE. Fallback: if world state unavailable, **passthrough camera dir** (stock).

### 7.2 Outputs

```text
sun_yaw_rad     // world-space direction for shadow stretch
length_scale    // multiplies DynamicShadow size axis used as “length”
visible         // false → treat as disabled / zero alpha path if stock allows
```

Geometry intent (document, not mandatory identical to Terminus):

```text
day:   length_scale from high (dawn) → low (noon) → high (dusk)
dusk:  long, fixed-ish yaw; fade visibility with progress
night: hidden unless fullmoon; then day-like with cooler look only if free
```

v1 **does not require** recolour (engine splat has no per-quad colour). Visibility can be “skip PopulateQuad” or size→0.

### 7.3 Camera independence

Acceptance criterion: rotate camera heading at fixed world time → **shadow ground direction stays fixed** (sun), while stock without plugin rotates with camera.

---

## 8. Hook contract (A)

### 8.1 Preferred algorithm

```text
original_GenerateVB(manager, component_vector):
  // stock builds dir from camera
hooked_GenerateVB(...):
  if !ShadowSunDrive or !sun_ok:
    return original(...)
  dir = from sun_yaw
  // either:
  // (1) reimplement loop calling original PopulateQuad + CreateVB  [LOCKED]
  // (2) detour only the cos/sin block — rejected (brittle)
  // (3) patch camera info then call original — rejected (global side effects)
```

**Locked:** resolve `PopulateQuad` + `CreateVB` + component list walk; reimplement loop using **original** `PopulateQuad`/`CreateVB`. Do **not** patch camera globals; do **not** cos/sin-only patch.

### 8.2 Threading

Render/cache thread only — same as stock GenerateVB. No Lua calls on render thread. Sun state updated from a safe tick (main/sim) into atomics/doubles read by hook.

### 8.3 Sticky hooks

`support_reload = false`. Unload: best-effort detach; document sticky like other render hooks.

---

## 9. Failure / degrade matrix

| Condition | Behaviour |
|---|---|
| Dedicated / non-Windows | `can_load` false |
| Symbol resolve fail | Feature off, inject continues |
| World state unreadable | Passthrough original GenerateVB |
| Config false | Passthrough |
| Exception in hook | Catch if project pattern allows; else fail-open to original once and disable |

---

## 10. Testing / verification

### 10.1 Automated (where possible)

- Plugin module loads under DynamicPluginLoader with schema keys present.
- Unit-level sun model pure functions: phase/progress → yaw/scale monotonicity tests (no game).

### 10.2 Manual / FE (required for D10)

| Check | Expect |
|---|---|
| `ShadowSunDrive=false` | Shadows match unmodded camera-follow behaviour |
| `=true`, fixed time, rotate cam | Shadow direction stable in world |
| Advance day | Length/yaw changes dawn→noon→dusk |
| Cave | No crash; **passthrough** stock GenerateVB (no sun drive) |
| With VBPool on/off | No crash; shadows still draw |
| With ANGLE non-auto | No crash |

### 10.3 Non-regression

- Static shadows still draw after `GenerateStaticShadows`.
- Entities without DynamicShadow unchanged.

---

## 11. Tier B reserve (not v1)

### 11.1 Intended data flow (future)

```text
visible casters (AnimState + policy)
  → read sBuild CPU verts / current frame elements
  → shadowMatrix(sun_yaw, length, ground)
  → pack BatchVertex colour=(0,0,0,a)
  → CreateVB (VBPool if present)
  → Draw few times with anim or simple black shader
```

### 11.2 Hard requirements when B is planned

- No global AnimState method table hook.
- No extra entity per caster.
- Feature flag default off.
- Fallback to A-only on any resolve failure.
- Separate implementation plan; this spec only freezes **non-conflict** with A (shared sun state module inside plugin).

### 11.3 Shared module inside plugin (v1 structure)

```text
plugin_render_shadow/
  plugin_render_shadow.cpp   // module init, schema, can_load
  SunModel.hpp/cpp           // pure math + state snapshot  [v1]
  GenerateVBHook.cpp         // tier A                       [v1]
  SilhouetteBatch.cpp        // stub or absent               [B later]
```

v1 may omit `SilhouetteBatch.cpp` entirely.

---

## 12. Alternatives considered

| Approach | Why not for v1 |
|---|---|
| Lua-only SetSize animation | Cannot fix camera-locked direction |
| Terminus-style entity clones in native | Same weight as mod; wrong direction |
| Hook DrawCacheRender shadow only | Dir already baked in VB; must fix at GenerateVB |
| True shadow maps | 2.5D mismatch; huge scope (D4) |
| A+B same milestone | User locked A ship + B design only |

---

## 13. Implementation slices (for later writing-plans)

| Slice | Deliverable | Gate |
|---|---|---|
| S0 | RE pin x64 `GenerateVB` / `PopulateQuad` / world time fields | addresses + dumpbin/cdb notes |
| S1 | Plugin skeleton + schema + can_load | loads, options visible |
| S2 | SunModel unit tests | pure tests green |
| S3 | GenerateVB hook + FE cam-rotate test | D10 |
| S4 | Docs: plugin-system table row + option help | docs |
| S5 | (future plan) SilhouetteBatch | separate plan |

---

## 14. Open items (bounded)

| ID | Item | Resolution rule |
|---|---|---|
| O1 | Exact Win64 RVAs / signatures | Closed in S0 before S3 merge |
| O2 | World time field offsets | Closed in S0; fallback passthrough |
| O3 | Whether length multiplies X or Y size axis | Match stock PopulateQuad usage (size vector axes as in GenerateVB locals) during S3 |
| O4 | Default `ShadowSunDrive` | **false** (safe); can flip after FE confidence |
| O5 | Seasonal alpha | Out of v1 unless free with existing texture path |

No unbounded TBDs: O1–O3 are implementation calibration, not design ambiguity.

---

## 15. Success criteria checklist

- [ ] `render.shadow` dynamic plugin follows `ds_plugin_module_init` pattern of `render.vbpool`.
- [ ] A: sun dir independent of camera when enabled.
- [ ] A: disabled = stock.
- [ ] Resolve failure does not break inject.
- [ ] B/C not implemented; no fake schema keys that claim B works.
- [ ] Spec matches one-plugin-one-duty: **sun-driven engine shadows**, not generic render framework.

---

## 16. Approval gate

After review of this file:

1. Adjust D\* / schema if needed.  
2. Invoke **writing-plans** for S0–S4 only (A path).  
3. Tier B gets its own plan when scheduled.

**Status after user approval of this file:** implement via `writing-plans` → phased plan under `docs/superpowers/plans/`.
