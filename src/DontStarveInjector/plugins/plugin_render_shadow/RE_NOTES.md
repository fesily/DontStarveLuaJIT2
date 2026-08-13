# render.shadow RE notes (Win64)

**Binary:** `C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/bin64/dontstarve_steam_x64.exe`  
**Ghidra program:** `dontstarve_steam_x64.exe`  
**Language:** x86:LE:64:default / windows  
**Image base:** `0x140000000`  
**Date:** 2026-08-11

World-time fields are **not** required in native for v1. Lua feeds `DS_LUAJIT_shadow_set_state(phase, progress, fullmoon)` (plan fallback).

---

## GenerateVB — `FUN_14008ba10`

| | |
|---|---|
| VA | `0x14008ba10` |
| RVA | `0x8BA10` |
| Body | `14008ba10` – `14008bbe9` |
| Callers | `FUN_14008bf20` (GenerateStaticVB), `FUN_14008c000` (DrawCacheRender dynamic path) |

**MSVC x64 thiscall:**

```text
void GenerateVB(ShadowManagerComponent *this,  // rcx
                vector<cEntityComponent*> *list); // rdx
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

**Camera dir (stock, to replace):**

```
cam = GetCurrentCameraInfo(sim)   ; FUN_1400fd240
angle = (cam->heading@+0x30 + C1) * C2
dir = { cosf(angle), sinf(angle) }  ; stack local_res8 / local_resc
```

`GetCurrentCameraInfo` = `FUN_1400fd240`.

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

---

## Size axes (O3)

Stock `SetSize(width, height)` → `{flSizeX, flSizeY}` both become ellipse radii, then rotated by `dir`.

**v1 length_scale multiplies `flSizeY` (+0x24) only** — second `SetSize` argument is the conventional depth/length of the blob. Width (`flSizeX`) stays.

If FE shows stretch on the wrong axis, flip to `flSizeX` (one-line change). Do **not** multiply both.

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

## World time (v1)

Native `TheWorld.state` offsets **not pinned**. Lua AfterModMain face calls:

```text
DS_LUAJIT_shadow_set_state(phase_id, timeinphase, isfullmoon)
```

Hook reads `ds::shadow::LoadPublished()` only.
