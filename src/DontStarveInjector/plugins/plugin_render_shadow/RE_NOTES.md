# render.shadow RE notes (Win64)

**Binary:** `C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/bin64/dontstarve_steam_x64.exe`  
**Ghidra program:** `dontstarve_steam_x64.exe`  
**Language:** x86:LE:64:default / windows  
**Image base:** `0x140000000`  
**Date:** 2026-08-11

World time comes from Lua `TheWorld.state` via `DS_LUAJIT_shadow_set_world`. Native `Evaluate(SunInput)` is the Terminus Light right-triangle formula. `set_sample` is gone.


---

## GenerateVB — `FUN_14008ba10`

| | |
|---|---|
| VA | `0x14008ba10` |
| RVA | `0x8BA10` |
| Body | `14008ba10` – `14008bbe9` |
| Returns | **`uint32_t` VB handle** (`CreateVB` EAX) or `0xFFFFFFFF` if no verts |
| Callers | `FUN_14008bf20` (GenerateStaticVB → store @ manager+0x30), `FUN_14008c000` (DrawCacheRender → store @ manager+0x34) |

**MSVC x64 thiscall:**

```text
uint32_t GenerateVB(ShadowManagerComponent *this,  // rcx
                    vector<cEntityComponent*> *list); // rdx
// EAX must be the CreateVB handle (or -1). A gum replacement that
// forgets to return it leaves static/dynamic splat handles garbage.
```

`std::vector` (MSVC): `begin` @ `+0x08`, `end` @ `+0x10` (8-byte pointers).

**Pattern (unique prologue, 33 bytes):**

```
48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 48 83 EC 50 48 8B 41 20 48 8B FA 48 8B F1 8B 90 D4 00 00 00
```

Disasm:

```
mov  [rsp+18h], rbx
mov  [rsp+20h], rbp
push rsi
push rdi
push r12
sub  rsp, 50h
mov  rax, [rcx+20h]          ; this->pShadowRenderer
mov  rdi, rdx                ; vector*
mov  rsi, rcx                ; this
mov  edx, [rax+0D4h]         ; vert-desc handle
```

**Camera dir (stock):**

```
cam = GetCurrentCameraInfo(sim)   ; FUN_1400fd240  (CALL @ GenerateVB+0x57)
angle = (cam->heading@+0x30 + 90°) * π/180
dir = { cosf(angle), sinf(angle) }
```

**Hook (current):** do **not** reimplement the loop. Save `heading`, write
`sun_yaw_deg - 90`, call **original GenerateVB**, restore. Length/visibility
stay on Lua `SetSize` / `Enable`.

Pointer chase (same as GenerateVB): `this+0x18` → entity; `entity+0xE0` → sim.

---

## PopulateQuad — `FUN_14008b680`

| | |
|---|---|
| VA | `0x14008b680` |
| RVA | `0x8B680` |
| Body | `14008b680` – `14008b97c` |

```text
void PopulateQuad(ShadowManagerComponent *this, // rcx (unused in body)
                  ShadowVertex *dest,           // rdx  — 6 verts, stride 0x14
                  Vector3 *pos,                 // r8   — xyz, y written as 0
                  Vector2 *size,                // r9   — {flSizeX, flSizeY}
                  Vector2 *dir);                // stack — {cos, sin}
```

**Pattern (24 bytes):**

```
4C 8B DC 48 81 EC A8 00 00 00 48 8B 84 24 D0 00 00 00
```

Half-extents: `sizeX * ±0.5`, `sizeY * ±0.5` (`0x3f000000` / `0xbf000000` at `140512098` / `140513480`). After each call GenerateVB advances dest by `0x78` (6 × `0x14`).

---

## splat.ksh (dst-ksh-analyze / length-prefixed parse)

Source: `Don't Starve Together/dst-scripts/shaders/splat.ksh` (1996B).

Uniforms: `MatrixP/V/W` (mat4), `SAMPLER[4]` (sampler2D), `LIGHTMAP_WORLD_EXTENTS` (vec4).

**VS** (`splat.vs`): `gl_Position = P*V*W * pos`; pass `TEXCOORD0` and world `MatrixW*pos`. No shear, no sun, no stretch.

**PS** (`splat.ps`): `texture2D(SAMPLER[0], uv) * lightmap(world.xz)`. No geometry. Blob looks circular because the texture is a blob; lean/length is 100% in `PopulateQuad` verts (`flSizeX` along `dir`, `flSizeY` perpendicular).

Implication: heading-only poke rotates a short ellipse — nearly invisible. Must multiply `flSizeX` by Terminus-like `length_scale` (noon 1.0, dawn/dusk ≈3.88).


## CreateVB

Called from GenerateVB as:

```text
CreateVB(this->pRenderer@+0x28, 10, vertCount, *(u16*)(vertDesc+8), verts, 0)
```

Do **not** invent a new CreateVB wrapper; call the same original after filling verts, or call original GenerateVB when passthrough.

---

## DynamicShadowComponent (x64)

| Off | Type | Name |
|-----|------|------|
| +0x18 | `cEntity*` | parent entity |
| +0x20 | `float` | `flSizeX` (`SetSize` first arg) |
| +0x24 | `float` | `flSizeY` (`SetSize` second arg) |
| +0x28 | `char` | `fEnabled` |

Skip if `fEnabled == 0` **or** `entity+0x1B4 != 0` (culled / hidden).

**Entity position:** `float xyz` at `entity+0x1F0`, `+0x1F4`, `+0x1F8`.

## Size axes (O3)

PopulateQuad treats `size = {flSizeX, flSizeY}` as local radii, then rotates by `dir=(cos θ, sin θ)`:

- **`flSizeX` (+0x20) lies along `dir`** (stretch / length)
- **`flSizeY` (+0x24) is perpendicular to `dir`** (width)

Stock θ is camera-derived `(heading + 90°) * π/180` (`C1` @ `140518704` = 90.0, `C2` @ `14061a520` = π/180), so in the *stock* frame Y looks like “length toward camera look.” That does **not** apply once `dir` is sun yaw.

**v1 pin:** set `dir = {cos(sun_yaw), sin(sun_yaw)}` and multiply **`flSizeX` only** by `length_scale`. Do not multiply both. Do not keep Y-as-length unless `dir` is also rotated −90°.

---

## Related (do not hook unless needed)

| VA | Role |
|---|---|
| `14008c000` | `TDataCacheShadowRenderer::DrawCacheRender` — `pass==2` @ camera+0x930; draws static VB then GenerateVB(dynamic list) |
| `14008bf20` | `GenerateStaticVB` — releases static handle @ manager+0x30, GenerateVB(static list) |
| `14008c140` | `ShadowRenderer` ctor — loads `shaders/splat.ksh` |
| `14008bc60` | `GetComponentList<DynamicShadowComponent>` |
| `14008bbf0` | `GetComponentList<StaticShadowComponent>` |

ShadowManagerComponent (x64, used in GenerateVB):

| Off | Name |
|-----|------|
| +0x18 | back-ref (entity / sim chain) |
| +0x20 | `ShadowRenderer*` |
| +0x28 | `Renderer*` |
| +0x30 | static VB handle (`-1` empty) |
| +0x34 | dynamic VB handle (`-1` empty) |

---

## World time

Lua AfterModMain pushes `TheWorld.state` only:

```text
DS_LUAJIT_shadow_set_world(phase_id, timeinphase_centi, time_centi, flags)
```

`Evaluate` is the SSOT (day/dusk lock / fullmoon / season / rain). Hooks read `LoadPublished()` only.



---

## Tier B (Win64)

Pinned 2026-08-14 on `dontstarve_steam_x64.exe` (image `0x140000000`) via Ghidra MCP. 32-bit `docs/ghidra-struct-analysis.md` is **not** Win64 truth.

### TDataCacheAnimNode::DrawCacheRender

| | |
|---|---|
| VA | `0x1400f0f00` |
| RVA | `0xF0F00` |
| Body | `1400f0f00` – `1400f20c7` |
| Ghidra | `FUN_1400f0f00` |
| Vtable | `PTR_FUN_140524280[0]` (TDC ctor `FUN_1400f6cf0` writes this vtable) |
| Size of TDC | alloc `0x200` in `AnimNode::DoCacheForRender` (`FUN_1400f7420`) |

**MSVC x64 thiscall** (only RCX/RDX used; extra dispatch args ignored):

```text
void DrawCacheRender(TDataCacheAnimNode *this,  // rcx
                     GameRenderer *renderer);   // rdx
```

32-bit `(GameRenderer*, Camera*, TRenderCache*)` is **not** the shipping Win64 contract. `rdx+0x930` is the **GameRenderer** pass field (same object used for `SetEffect` / `SetVertexDescription` / `Draw`). There is no separate Camera* argument on this function.

**Pattern (unique prologue, 32 bytes)** — one hit @ `1400f0f00`:

```
40 53 57 41 56 48 81 EC 90 04 00 00 48 8B D9 48 8B 8A 20 09 00 00 48 8B FA 48 8B 49 28
```

Disasm:

```
push rbx
push rdi
push r14
sub  rsp, 490h
mov  rbx, rcx                    ; this = TDC*
mov  rcx, [rdx+920h]             ; renderer->pSomething
mov  rdi, rdx                    ; GameRenderer*
mov  rcx, [rcx+28h]              ; Batcher*
call Batcher_Flush               ; FUN_140036360
```

Then `sAnim::GetFrame` (`FUN_14016ec50`) on `this+0xB0` with playMode `this+0xC0` and time `this+0xC4`. Null frame → return.

Inner element loop is `FUN_1400eff60` (`1400eff60`–`1400f0ef8`), called after node-level effect/vert-desc setup.

### TDataCacheShadowRenderer::DrawCacheRender

| | |
|---|---|
| VA | `0x14008c000` |
| RVA | `0x8C000` |
| Body | `14008c000` – `14008c104` |
| Ghidra | `FUN_14008c000` |

```text
void DrawCacheRender(TDataCacheShadowRenderer *this,  // rcx
                     GameRenderer *renderer);         // rdx
```

Body runs **only** when `*(int32*)(renderer + 0x930) == 2`. Then: `SetEffect(this+0x18)`, `SetVertexDescription(this+0x1c)`, `SetTexture(0, this+0x20)`, draw static VB @ manager+0x30, `GenerateVB` dynamic list → manager+0x34, draw, `ReleaseVB`.

TDC Shadow: `+0x18` effect, `+0x1c` vert-desc, `+0x20` splat tex, `+0x28` `ShadowManagerComponent*`.

**Pattern (unique prologue, 33 bytes)** — one hit @ `14008c000`.
Do **not** use the first 24 bytes alone (`48 89 74 24 10 57 48 83 EC 20 83 BA 30 09 00 00 02`); that prefix also appears mid-function at `1400f9bb5`.

```
48 89 74 24 10 57 48 83 EC 20 83 BA 30 09 00 00 02 48 8B FA 48 8B F1 0F 85 DD 00 00 00
```

Disasm:

```
mov  [rsp+10h], rsi
push rdi
sub  rsp, 20h
cmp  dword ptr [rdx+930h], 2
mov  rdi, rdx                    ; GameRenderer*
mov  rsi, rcx                    ; this
jnz  ret
```

### Pass order (shipping client)

`cGame::DrawCacheRender` `FUN_140014a50` → `CacheWorldRender` `FUN_140014410`:

```text
for pass in {0,1,2}:            // skip if that pass's RT handle == -1
    *(uint32*)(GameRenderer + 0x930) = pass
    // 0 = "Z-Prepass", 1 = "Bloom", 2 = "Normal"
    for each layer in cache+0x450 (count @ cache+0x468, stride 0x30):
        for each TDC* node:
            owner = *(node + 8)           // AnimNode* / SceneGraphNode*
            owner->vtable[0x38](owner, GameRenderer, node, ...)
```

This is **not** the 32-bit “anim pass==1 / shadow pass==2” split. Both Anim DCR and Shadow DCR see the same `GameRenderer+0x930`:

| pass | name | Anim DCR | Shadow DCR |
|---|---|---|---|
| 0 | Z-Prepass | runs (if RT present) | no-op |
| 1 | Bloom | bloom shader branch (`AnimManager+0x124` etc.) | no-op |
| 2 | Normal | color draw; optional 2-pass stencil | **draws splat + GenerateVB** |

**Collect** after original color draw only when `renderer+0x930 == 2` (otherwise bloom/z-prepass would double-pack).

Anim vs Shadow **layer order inside pass 2 is UNPINNED**. If the shadow layer is submitted before anim nodes, a same-pass collect-then-flush races (flush sees an empty batch). Task 5 must not assume collect happens before Shadow DCR; if layer order is shadow-first, defer flush to end of pass 2 / next safe point.

**Task 5 flush placement (2026-08-14, fixed same day):** Intra-pass Anim vs Shadow order is still UNPINNED. Pre-collect stays at `CacheWorldRender` `FUN_140014410` **entry** (unique prologue `48 89 54 24 10 56 41 56 48 81 EC 58 02 00 00 48 8B F1 48 8B 89 70 01 00 00`). Walk layers (`+0x450` / count `+0x468` / stride `0x30`, TDC vec `+0x18/+0x20`) and pack any TDC whose **vtable[0]** (`**(void***)tdc`, slot 0 of `PTR_FUN_140524280`) equals the scanned Anim DCR `0x1400f0f00`. Do **not** compare `*(void**)tdc` (that is the vtable pointer itself). Shadow DCR is original-only (no flush/clear). Flush is **not** after `CacheWorldRender` returns — that is after `FUN_1403dc3e0` (`glBindFramebuffer(0x8d40, 0)`) and PostProcess. Gum-replace `FUN_1403dc3e0` (unique 20B `40 53 48 83 EC 20 44 8B 49 0C 44 8B 41 08 48 8B D9 33 D2 33 C9`, one hit @ `1403dc3e0`). If `renderer+0x930==2` and a pass-2 DCR has run this frame (`pass2_dcr_seen`; needed because `FUN_140022c60` unbinds first with leftover `0x930`) and B is healthy: `FlushSilhouettes(renderer)` then original unbind. `ClearSilhouetted` after that flush (and again after `CacheWorldRender` as a skip-pass safety).

### Entity from TDC / AnimNode

TDC ctor `FUN_1400f6cf0(tdc, animNode, matrix)`:

| TDC off | Type | Source |
|---|---|---|
| +0x00 | vtable | `PTR_FUN_140524280` |
| +0x08 | `AnimNode*` | ctor `param_2` |
| +0x10 | u16[2] | `0xFFFF` or `**(AnimNode+0xA0)` (layer/scissor) |
| +0x18 | `float[16]` | world matrix (DoCache `param_2`) |
| +0xB0 | `sAnim*` | `AnimNode+0xD0` |
| +0xB8 | `sBuild*` | `AnimNode+0xD8` |
| +0xC0 | u32 | playMode `AnimNode+0x114` |
| +0xC4 | float | time `AnimNode+0x118` |
| +0xCC | u32 | vert-desc `AnimNode+0x12C` |
| +0x128 | `AnimNode*` | same as +0x08 |
| +0x138 | u32 | effect handle `AnimNode+0x134` |

`SceneGraphNode` / `AnimNode` (ctor `FUN_140034710` + `FUN_1400f4b60`):

| Off | Type | Name |
|---|---|---|
| +0x4C | u32 | layer (set 6 or 8 in AnimState init) |
| +0x52 | u16 | **entity GUID** — copied from `entity+0x08` in `FUN_14009e0f0` |
| +0x60/68/70 | vec | children |
| +0x78 | `cGame*` | `pGame` |
| +0x90 | `SceneGraphNode*` | parent (AddChild from `entity+0x108` or `+0x110`) |
| +0xD0 | `sAnim*` | |
| +0xD8 | `sBuild*` | |

`cGame+0x70` = `AnimManager*` (used as `*(*(AnimNode+0x78)+0x70)` in Anim DCR — last `*` loads the pointer stored at `cGame+0x70`). `cGame+0x28` = sim (same object GenerateVB uses via `entity+0xE0`). `sim+0xA0` = entity manager (`FUN_14008bc60`).

**There is no `*(AnimNode+X) = cEntity*` load.** Forward entity* from TDC is not a single offset.

Proven reverse (use this for SilhouettedSet):

```text
entity+0x1D0  → AnimStateComponent*     // fast slot, FUN_1401198a0
AnimState+0x18 → cEntity*                // every cEntityComponent
AnimState+0xF0 → AnimNode*               // FUN_14009e0f0
```

Collect can mark `AnimNode*` (`tdc+0x08`). GenerateVB skip:

```text
animState = *(entity + 0x1D0)
if (animState && *(animState + 0xF0) is in SilhouettedSet) skip
```

If Task 5 requires `entity*` at collect time: scan the current DynamicShadow vector (same list GenerateVB walks) and match `GetComponent(comp+0x18, AnimStateHash)->pAnimNode == tdc+0x08`. Do **not** invent an AnimNode→entity pointer.

### HasDynamicShadow(entity)

Type hash `0x56462bdf` (`FUN_14008b520` returns it).

Cheapest per-entity test — `cEntity::GetComponent` `FUN_140117110`:

```text
cEntityComponent* GetComponent(cEntity* entity, uint32_t typeHash)
// binary-searches entity+0xF0 .. entity+0xF8 (vector<cEntityComponent*>)
// compares vtable+0x30() to typeHash
```

```text
bool HasDynamicShadow(entity):
    comp = FUN_140117110(entity, 0x56462bdf)
    return comp != NULL
        && *(char*)(comp + 0x28) != 0          // fEnabled
        && *(char*)(entity + 0x1B4) == 0       // not culled (same as GenerateVB)
```

AnimState type hash is `0x1F59DA00` (`FUN_140097cf0`) if a second GetComponent is needed.

Equivalent list walk (already in GenerateVB): `FUN_14008bc60(sim+0xA0)` → object whose `+0x08`/`+0x10` are `begin`/`end` of `DynamicShadowComponent*`. Each `comp+0x18` is `entity*`. Membership in that vector **and** `fEnabled` is the same test GenerateVB uses.

Do **not** call Lua.

### sBuild CPU verts + visible element loop

`sBuild::GetFrame` `FUN_14016f130` (binary search):

| sBuild off | Type | Name |
|---|---|---|
| +0x58 / +0x60 | `u32*` | texture-handle vector begin/end (`ApplyTextures` `FUN_14016f050`) |
| +0x70 | `sBuildSymbolEntry*` | symbols, stride **0x20**, count @ +0xA0 |
| +0x80 | u32 | primary GPU VB handle (`CreateVB` type 9, 16B converted verts) |
| +0x84 | u32 | secondary GPU VB handle (`-1` none) |
| +0x88 | `float[2]*` | **XY-only** CPU cache (8B/vert, `FUN_140167810`; asserts `z==0`) |
| +0x90 | `void*` | secondary **24B** CPU copy (build.bin version **< 5** only) |
| +0x98 | u32 | `numVerts` primary |
| +0x9C | u32 | `numVerts2` secondary |
| +0xA0 | u32 | `numSymbols` |
| +0xA8 | char | textures loaded |

`sBuildSymbolEntry` (x64): hash @ +0x00, `pFrames` @ +0x10, `numFrames` @ +0x18.

`sBuildSymbolFrame` stride **0x34** (same as 32-bit):

| Off | Name |
|---|---|
| +0x00 / +0x04 | frameStart / frameCount |
| +0x08 / +0x0C | `vertexStart` / `vertexCount` (primary, `sBuild+0x80`) |
| +0x10 / +0x14 | `vertexStart2` / `vertexCount2` (secondary, `sBuild+0x84`) |

`sFrame` (from `FUN_14016ec50` = `sAnim+8 + index*0x28`):

| Off | Name |
|---|---|
| +0x18 | `sAnimElement* pElems` |
| +0x20 | `numElems` |

`sAnimElement` stride **0x30**. Hidden-layer skip: binary search TDC hidden vector (passed as Anim DCR `this+0x140`). Override build is **pinned** from `FUN_1400f0f00` → `FUN_1400eff60` (`param_6 = TDC+0x160`; `FUN_1400eea40` inlined):

```text
map = TDC+0x160
empty if *(map+0x10)==0
header = *(map+0x08); root = *(header+0x08)
walk BST: key = elem+0x10 (symbol hash) vs node+0x18
  node+0x00 left, +0x08 parent, +0x10 right, +0xA9 _Isnil
hit: obj = node+0x28
  (*obj & 1)  → skip element
  (*obj & 0x10) && *(obj+0x58)!=0 → GetFrame on that sBuild*
  else → GetFrame on TDC+0xB8
```

Flag `0x10` is the first byte of the override object, not a TDC field.

Color-pass draw (do **not** reimplement for collect; copy the same ranges):

```text
if (build->vb2 != -1 && frame->vertexCount2) Draw(vb2, frame->vertexStart2, count2)
if (build->vb  != -1 && frame->vertexCount)  Draw(vb,  frame->vertexStart,  count)
```

**Win64 flush (sil-r, Android DrawFrame contract):** do **not** `CreateVB`. Pack records
`sBuild+0x80/+0x84` GPU handles + `sBuildSymbolFrame` `start/count`. After the first
pass-2 Anim Draw (color `anim.ksh` already bound), `SetTexture` + `SetVertexBuffer(vb)`
+ `Draw(flattenMatrix, start, count, 6)`. Do **not** `SetEffect` (handle write only;
`HWEffect.src_data` stays from the color pass). Win64 `VertexDescription+8` is **not**
a uint16 stride (`0x2A80` observed) — do not gate flush on that field.


`elemFinal = passMatrix * elemAffine` via `FUN_1400efaa0` then `FUN_14000af10`.

**Primary 24B CPU array is not retained** after `AnimationFile::LoadFile` (`FUN_14016b630` → `FUN_14016ec80`). Load converts 24B file verts → 16B temp → `CreateVB(..., stride=0x10)` @ `sBuild+0x80`, then frees the temp; only XY remains at `+0x88`. GPU layout (pinned from `FUN_14016ec80` + `FUN_1403e62f0(desc, 0, 0, 4)` + `DAT_140511cc4 = 2.0f`): `{float x, float y, bitcast_f32(rgba)*2.0f + u, float v}`. File/CPU 24B is still `{float3 pos, float2 uv, RGBA8}`; z is dropped. `CreateVB` memcpy's `count * stride` (`FUN_1403e2d10`).

**Minimal pack (v1):**

1. `sFrame* = GetFrame(tdc+0xB0, tdc+0xC0, tdc+0xC4)` — same as DCR.
2. For `i in [0, sFrame+0x20)`: `elem = *(sFrame+0x18) + i*0x30`; skip hidden; walk TDC+0x160 then `GetFrame` on override `sBuild*` or `tdc+0xB8`.
3. Transform the **same** `vertexStart`/`vertexCount` (and secondary if `+0x90` present) by the same `elemFinal` DCR already computed, then flatten Y / sun yaw (Task 5).
4. CPU source: secondary `sBuild+0x90` (24B) when `numVerts2 != 0`; else **XY-only** `sBuild+0x88` (UV=0, A=255) — **will not** alpha-cut `anim.ksh`. Do not invent a primary 24B base.

Flatten multiply: apply `elemFinal` (passMatrix × elem affine, already includes TDC world @ `+0x18` + billboard from `CalculateScaleMatrix` `FUN_1400eee70` / facing `TDC+0x60` / billboard `TDC+0x64`) then force `y=0` and sun stretch. Do **not** replace passMatrix with world-only or facing is wrong.

`CalculateScaleMatrix` / `mat_mul` Rel32 come from the scanned Anim DCR
(`+0xA4` / `+0xF9`). Passing `anim_dcr=0` into `BindSilhouetteHelpers` leaves
`calc_scale=null` and pack uses world-only `TDC+0x18`. Flatten then collapses
the un-billboarded XY sprite to a ground line — flush reports `ok>0` but
nothing is visible. Scan Anim DCR for Rel32 only; do not gum-replace it.


### anim.ksh / vert-desc (flush)

**Not splat.** `shaders/anim.ksh` is loaded; do not fall back to `splat.ksh`.

**VS/PS contract (dst-scripts/shaders/anim.ksh, 747465):**

```glsl
attribute vec4 POS2D_UV;           // x, y, u + samplerIndex*2, v   — no RGBA
vec3 POSITION = vec3(POS2D_UV.xy, 0);
vec4 world_pos = MatrixW * vec4(POSITION, 1.0);   // GLSL column-major
gl_Position = (MatrixP * MatrixV) * world_pos;
PS_POS = world_pos.xyz;            // lightmap / ocean use PS_POS.xz
// PS: gl_FragColor = texture * COLOUR_XFORM;  rgb = min(rgb, a)
// if (FLOAT_PARAMS.y > 0 && PS_POS.y < FLOAT_PARAMS.x) discard;
```

No sun, no flatten, no shadow in the shader. Flatten **must** live in `MatrixW`.
Black **must** be `COLOUR_XFORM` (GPU VB has no vertex color).

Win64 `FUN_1403dc6f0` (hooked Anim Draw): `SetUniform(renderer, 7, matrix)` then
`FUN_1403e64b0` storage-converts **row-major C → column-major GL**. CPU `m[4..7]`
is the world-Y output row (`wy = m[4]x+m[5]y+m[6]z+m[7]`). `m[3],m[7],m[11]`
are translation. Writing `m[12..15]` (homogeneous row) explodes clip-w (sil-w streaks).

`FLOAT_PARAMS.y>0` discards flattened `y=0` fragments — keep a small `m[7]` if needed.


`AnimManager` shader init `FUN_14016d800` (`..\\source\\animlib\\animmanager.cpp`):

| AnimManager off | Handle |
|---|---|
| +0x118 | `shaders/anim.ksh` |
| +0x11C | `shaders/anim_fade.ksh` |
| +0x120 | `shaders/anim_haunted.ksh` (fallback anim.ksh) |
| +0x124 | `shaders/anim_bloom_haunted.ksh` |
| +0x128 | `shaders/anim_fade_haunted.ksh` |
| +0x12C | `shaders/anim_holo.ksh` |
| +0x130 | vertex-description handle (`FUN_1403e2790`) |
| +0x13C | `images/trans.tex` |

Chase: `AnimManager* = *(*( *(tdc+0x08) + 0x78 ) + 0x70)` (`animNode = *(tdc+0x08); game = *(animNode+0x78); animMgr = *(game+0x70)`). Last dereference is required — without it the expression is the address of `cGame+0x70`, not the pointer stored there. Anim DCR loads `RSI = [[AnimNode+0x78]+0x70]` before reading `+0x118`/`+0x130`.

Per-node handles the color pass actually binds (prefer these for flush so haunted/fade match the entity):

```text
SetVertexDescription(renderer, tdc+0xCC)   ; FUN_1403de520
SetEffect(renderer,            tdc+0x138)  ; FUN_1403db850
```

v1 silhouette flush: `anim.ksh` = `AnimManager+0x118` (or `DAT_14061e070` from `FUN_140165960`) + vert-desc `tdc+0xCC` / `AnimManager+0x130`. Upload **16B** LoadFile verts (drop if vert-desc `+8` stride != 16). Black multiply in CPU color; keep source A if a 24B/UV source exists.

Renderer helpers used by both DCRs:

| VA | Role |
|---|---|
| `1403db850` | `SetEffect(renderer, handle)` |
| `1403de520` | `SetVertexDescription(renderer, handle)` |
| `1403dc360` | `SetTexture(renderer, slot, handle)` |
| `1403db860` | `SetVertexBuffer` |
| `1403dc7d0` / `1403dc6f0` | `Draw` (shadow uses `1403dc7d0`; anim inner uses `1403dc6f0`) |

Globals (GameRenderer-side, `FUN_140165960`): `DAT_14061e070` = anim.ksh, `DAT_14061e074` = anim_skinned.ksh, `DAT_14061e078` = anim_bloom.ksh, `DAT_14061e07c` = anim_bloom_skinned.ksh.

### Hook targets (Task 5)

| Symbol | Pattern (scan all hits, use **lowest** address = entry) |
|---|---|
| Shadow DCR | `48 89 74 24 10 57 48 83 EC 20 83 BA 30 09 00 00 02 48 8B FA 48 8B F1 0F 85 DD 00 00 00` |
| CacheWorldRender | `48 89 54 24 10 56 41 56 48 81 EC 58 02 00 00 48 8B F1 48 8B 89 70 01 00 00` |
| Unbind FBO | `40 53 48 83 EC 20 44 8B 49 0C 44 8B 41 08 48 8B D9 33 D2 33 C9` |
| sAnim::GetFrame | `48 83 EC 28 4C 8B C9 E8 ?? ?? ?? ?? 83 F8 FF 74 13 8B C0 48 8D 14 80` |
| Anim Draw (FUN_1403dc6f0) | `48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B 01 41` |
| GenerateVB | existing A pattern; reuse `GetGenerateVBAddress()` (do not rescan after replace) |

Do **not** locate these by image RVA. Mid-function clones exist; `ScanLowest` takes the first (lowest) hit.

Gum: `ds::gum::replace` Shadow DCR, CacheWorldRender, Unbind only. **Do not hook Anim DCR** — its scan lands mid-function and pack/draw from that site crashes HWEffect. GetFrame and Draw are bound by signature, not Rel32 from Anim. Shadow Rel32 still binds set_effect/set_tex/get_ds_list. PreCollect walks every cache-layer node and packs only if `EntityFromTdcViaDsList` matches.

CacheWorldRender (`game.cpp`) walks `cache+0x450` layers. Each slot is a **node**,
not an Anim TDC: `inner = *(node+8); inner->vt[0x38](inner, renderer, node, ...)`.
On the crashing session those 4 nodes had `vt[0] == Shadow DCR` (ellipse
drawables). Packing the node as an Anim TDC reads `+0xB0/+0x138` off-object and
feeds HWEffect a garbage handle (`src_data == NULL`). PreCollect must skip
Shadow DCR `vt[0]` and only pack `inner` when `inner+0xB0/0xB8` look like sAnim/sBuild.




Collect keys `entity*` from DS `comp+0x18` (must match GenerateVB mute). Scan: `*( *(entity+0x1D0) + 0xF0 ) == *(tdc+0x08)`.

## Own pipeline S0 (2026-08-15)

Shipping `dontstarve_steam_x64.exe` 747465. Rel32 from `BindSilhouetteHelpers`: `sd+0x28` = `SetEffect` `FUN_1403db850`.

### BindProgram
- VA: `0x1403e92f0` (`FUN_1403e92f0`, HWEffect vtable[+0x10], Ghidra `PTR_FUN_1405a8f48[2]`)
- Signature: `void __fastcall HWEffect_Bind(HWEffect *this, void *shader_constant_set, uint8_t *renderer_plus_0x10)`
  - `this` = `Get(*(void**)(renderer+0x1B8), *(uint32_t*)(renderer+0x2C))` (`FUN_1403dc420`)
  - `shader_constant_set` = `*(void**)(renderer+0x188)`
  - `renderer_plus_0x10` = `(uint8_t*)renderer + 0x10`
  - There is **no** `BindProgram(renderer, handle)` on GameRenderer. `SetEffect` is not this.
- Proof: if `*(int32*)(r8+0x18) != *(int32*)(r8+0x1c)` (i.e. `renderer+0x28 != renderer+0x2C`) the body does `glUseProgram(*(uint32_t*)(this+0xEC))` then copies `renderer+0x2C → renderer+0x28`. It then commits VS/PS uniforms via `FUN_1403e8c40(this+8 / this+0x60, this+0x158, constants, r8)`.
  - `HWEffect.src_data` chase: `renderer+0x1B8` → EffectManager* → `Get(mgr, *(uint32_t*)(renderer+0x2C))` → `HWEffect*`. Stable per-effect blob is `*(void**)(fx+0xB8)` (`mRawData`, written in `FUN_1403eb580`). GL program is `*(uint32_t*)(fx+0xEC)`.
  - The crash assert `"src_data != NULL"` (`HWEffect.cpp` 0x1d3) is **inside** `FUN_1403e8c40`: a ShaderConstantSet hash lookup. Garbage handle → `Get` yields a bad `HWEffect*` → lookup misses → `src_data == NULL`.
  - After `HWEffect_Bind` on a different effect, `Get(mgr, renderer+0x2C)+0xB8` is that effect's blob (not splat). `SetEffect` at the bound Rel32 (`FUN_1403db850`, `sd+0x28`) stores `*(uint32_t*)(renderer+0x1C) = handle` and **does not** change `renderer+0x2C` or `fx+0xB8`.
- Pattern (unique prologue, ScanLowest): `48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 41 8B 40 1C` (1 hit @ `1403e92f0`)

Shadow DCR (`FUN_14008c000`) from first `SetEffect` through first `Draw` — every `E8` and dest write. **None** is BindProgram:

| Call | VA | Dest write |
|---|---|---|
| `SetEffect` | `1403db850` (`sd+0x28`) | `renderer+0x1C` (uint32 handle only) |
| `SetVD` | `1403de520` (`sd+0x33`) | `renderer+0x2C` (uint32 handle only) |
| `SetTexture` | `1403dc360` (`sd+0x41`) | `renderer+0x34+4*slot` + `glBindTexture` |
| `SetVB` | `1403db860` (`sd+0x55`) | `renderer+0x14` (uint32 handle only) |
| `Draw` | `1403dc7d0` (`sd+0x63`) | `renderer->vt[2]()` then `FUN_1403dc520` then **`HWEffect_Bind`** |

Field use in `FUN_1403dc520` / `Draw`: `renderer+0x1C` is looked up in the **vert-desc** manager (`renderer+0x1A0`); `renderer+0x2C` is looked up in the **effect** manager (`renderer+0x1B8`). So `BindSilhouetteHelpers` names are swapped vs Draw: `sd+0x28` writes the vert-desc handle, `sd+0x33` writes the effect handle Draw binds. TDC Shadow `this+0x18` is the first Set* arg (vert-desc / `ShadowRenderer+0xD4`); `this+0x1C` is the effect handle (`ShadowRenderer+0xD8`).

### LoadShader
- VA: `0x1403e9f00` (`FUN_1403e9f00`, `ResourceManager::Load`). Unique prologue `40 53 55 56 57 41 54 41 55 41 56 48 81 EC 00 01 00 00` on live `dontstarve_steam_x64.exe`. Ghidra `FUN_1403e2970` / RVA `0x3e2970` was a mid-function hit (live bytes `8d 54 24 68…`), not the entry. EffectManager vtable `PTR_LAB_1405a7a20[+0x38]` is thunk `FUN_1403e30f0` (2 hits, not unique) that copies the stack extra and calls this.
- Signature:
  ```text
  uint32_t __fastcall LoadShader(EffectManager *this, // rcx = *(renderer+0x1B8)
                                 const char *path,    // rdx
                                 bool log_error,      // r8  (1 in ShadowRenderer ctor)
                                 bool do_fallback,    // r9  (0); forwarded into DoLoad
                                 uint32_t extra);     // stack (0)
  ```
  Miss → `this->vt[1]` = `FUN_1403e8050` (`new` 0x1F0 `Effect` / `FUN_1403ebef0` → `HWEffect` ctor `FUN_1403eb580` → `FUN_140180730(path)`). Hit → bump slot refcount, return existing handle.
- Proof: ctor `FUN_14008c140` does `LoadShader(*(renderer+0x1B8), "shaders/splat.ksh", 1, 0, 0)` and stores EAX at `ShadowRenderer+0xD8`. A later `LoadShader` of the same path returns that cached handle (name map at manager+0x58). TDC Shadow DCR consumes it as `this+0x1C` (see swap note above). `DoLoad` failure with `log_error` prints `Error loading %s resource %s. Is the filename case correct?`.
- Search path (`FUN_140180730` walks mounted FS, `vtable[+0x20]` Open; cwd after `SetCurrentDirectoryW(L"../data")` is the game `data/` folder):
  1. DEV disk FS mounted as `"DEV"` (`FUN_1401be970` / `FUN_14017f110`): `fopen` of `(FS+0x120="") + path` after `GetLongPathNameA`. **Absolute paths work.** Relative `Mod/plugins/plugin_render_shadow/shaders/sil.ksh` resolves under `data/` and **does not** work. `dst-scripts/shaders/` (game-root loose tree) is **not** searched.
  2. Same FS workshop remap (`../mods/workshop-` + id) — only workshop content.
  3. Zip `DEV=databundles/shaders.zip` (`FUN_140181110` / `FUN_1404d8ff0`): exact member. Shipping `shaders/splat.ksh` is in this zip (68 members, prefix `shaders/`).
  4. Other DEV zips: `klump.zip`, `fonts.zip`, `anim_dynamic.zip`, `bigportraits.zip`, `images.zip`, `scripts.zip` — no splat.
  Loose `data/shaders/` and `data/databundles/shaders/` do **not** exist. A file we own loads if passed as an **absolute** path; the zip-only relative name `shaders/*.ksh` is shipping content.

- Pattern (unique prologue, ScanLowest): `40 53 55 56 57 41 54 41 55 41 56 48 81 EC 00 01 00 00` (1 hit @ `1403e2970`)

### CreateVB fmt
- GenerateVB call: `CreateVB(renderer, 10, vertCount, *(uint16_t*)(vertDesc+8), verts, 0)`
  - `CreateVB` = `FUN_1403e2d10` (Rel32 `gv+0x1A9`)
  - `TYPE` = `uint16_t`, `OFF` = `8`
  - `vertDesc` = `Get(*(void**)(renderer+0x1A0), handle)` (`FUN_1403dc420` returns the object pointer at slot+8, not the slot)
- Splat vert-desc (ShadowRenderer ctor `FUN_14008c140`): `Set(0, 0, 3)` then `Set(1, 0, 2)` on `FUN_1403e62c0` builder. `*(uint16_t*)(desc+8)` live value **`0x14`**.
- Anim vert-desc live values: `AnimationFile::LoadFile` `FUN_14016ec80` calls `CreateVB(..., 9, count, 0x10, ...)` with literal **`0x10`**. GameRenderer `+0x950` builder is `Set(0, 0, 4)` then `Set(1, 0, 2)` → `*(uint16_t*)(desc+8)` **`0x18`**. Use the LoadFile `0x10` for 16B anim GPU verts; do not take `+0x950` as that fmt.
- `CreateVB` uses `param_4` as `memcpy` size `vertCount * param_4` (`FUN_1403e2d10`). `HWVertexDescription::Set` (`FUN_1403e62f0`) also accumulates that same `+8` field. **Do not claim `fmt == stride`** — pass the object field (or the LoadFile literal `0x10` for 16B anim verts). Prior live dump `0x2A80` is **not** `Get()`'s object+8 (that value matches reading a resource **slot**+8 as uint16, i.e. the low bits of the object pointer).

- **Live 747465 (CDB 2026-08-16):** `0x3e62c0` is `dec r9d` inside `ShaderConstantSet`
  (`mFreeConstantIdx + num_floats <= MAX_NUM_FLOATS`, `ShaderConstantSet.h:274`).
  `0x3e62f0` is mid-instruction. Calling them as `HWVertexDescription::{ctor,Set}`
  asserts ~10s after B enable (FE pass-2 Shadow DCR). Steal `AnimManager+0x130`.




## sil.ksh reflection (Task 2)

Shipping container walked on `dst-scripts/shaders/splat.ksh` (1996 B = `0x7CC`) before
splicing. Parser is `FUN_1403ec440` → `FUN_140433e70` (lp string) / `FUN_1403ec0a0`
(uniform table) / `FUN_1403eaad0` (VS) / `FUN_1403eb130` (PS) / `FUN_1403eabb0`
(VS then PS uniform-index lists). `FUN_1403ec550`: types `0x2A..0x2D` (sampler2D=43)
have no default payload.

Record (engine, little-endian):

```text
u32 name_len + name
u32 uniform_count
for each uniform:
  u32 name_len + name
  u32 alias_len + alias     ; splat always 0 (empty). dst-ksh-analyze calls this "scope"
  u32 type                  ; 0=float 2=vec2 3=vec3 4=vec4 20=mat4 43=sampler2D
  u32 array_len             ; 1 if not an array
  if type not in 0x2A..0x2D:
    u32 default_count
    default_count * u32     ; zeros in splat
u32 vs_name_len + vs_name
u32 vs_src_len + vs_src     ; includes trailing NUL
u32 ps_name_len + ps_name
u32 ps_src_len + ps_src     ; includes trailing NUL
u32 vs_index_count + vs_index_count * u32   ; indices into uniform table
u32 ps_index_count + ps_index_count * u32
```

splat.ksh offsets (file start = 0):

| off | end | field |
|-----|-----|-------|
| 0000 | 0009 | name `splat` (len 5) |
| 0009 | 000d | uniform_count = 5 |
| 000d | 0068 | `MatrixP` scope/alias=0 type=20 array=1 default_len=16 (64 B zeros @0028) |
| 0068 | 00c3 | `MatrixV` same |
| 00c3 | 011e | `MatrixW` same |
| 011e | 0135 | `SAMPLER` alias=0 type=43 array=4 (no defaults) |
| 0135 | 016f | `LIGHTMAP_WORLD_EXTENTS` alias=0 type=4 array=1 default_len=4 |
| 016f | 017b | vs_name `splat.vs` |
| 017b | 0318 | vs_src 409 B (NUL-terminated GLSL) |
| 0318 | 0324 | ps_name `splat.ps` |
| 0324 | 07b0 | ps_src 1160 B (NUL-terminated GLSL) |
| 07b0 | 07c0 | vs_index_count=3 → 0,1,2 (`MatrixP/V/W`) |
| 07c0 | 07cc | ps_index_count=2 → 3,4 (`SAMPLER`, `LIGHTMAP_WORLD_EXTENTS`) |

`sil.ksh` is the same container, name `sil`, three uniforms (`MatrixP`, `MatrixV`,
`SAMPLER[4]`), no `MatrixW` / `LIGHTMAP_WORLD_EXTENTS` / `FLOAT_PARAMS`. VS:
`P*V*vec4(POSITION.x, 0, POSITION.y, 1)`, `POSITION` = `{x,z,u,v}` (engine attrib
slot 0). PS: black × `SAMPLER[0].a`, discard if `a < 1/255`. VS indices 0,1; PS
index 2. Vert-desc: `FUN_1403e62c0` + `Set(0,0,4)` + `FUN_1403e2790` on
`*(renderer+0x1A0)`. Load: `FUN_1403e2970(*(renderer+0x1B8), abs_path, 1, 0, 0)`.
`cGame+0x48` is GameRenderer (`FUN_140014a50`).

