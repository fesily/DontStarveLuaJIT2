# Blob Split A — 内部布局证据

program: `dontstarve_steam` (macOS i386). 只读反编译/布局调查。
(scout EPERM, 主 agent 物化)

汇总: **可拆 4 / 需更多调查 0**

---

## WaveComponent.pVec_0x64 @ 0x64 (12B)

当前 layout: `byte[12] pVec_0x64` at offset 100 (struct 绝对 0x64)。

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| 0x64 | 4 | float | flWidth | ctor @0x8979c: Zero 复制 8B 到 [0..7] + 4B 清零; DoRender @0x89e90 读 `*(float*)(this+0x64)` 参与 ceilf/fmod |
| 0x68 | 4 | float | flHeight | ctor 第二 float; DoRender 读作为高度, 与 nNumWaves 组合波间距 |
| 0x6C | 4 | int | nNumWaves | ctor 写 0; SetRegionNumWaves @0x8a5de 写; DoRender 当整数除法 |

### 建议替换
```
float flWidth;   // +0x64
float flHeight;  // +0x68
int   nNumWaves; // +0x6C
```

---

## cNetworkManager.wField_0x8E @ 0x8E (2B)

当前 layout: `ushort wField_0x8E`。

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| 0x8E | 1 | byte | bPad_0x8E | ctor @0x165992: wField_0x8E=0x100 → [0x00,0x01], 0x8E 无读写 |
| 0x8F | 1 | bool | bAutosaverEnabled | LoadSettings @0x166a6a: "autosaver_enabled" SETZ [EDI+0x8F]; GetAutosaverEnabled @0x195516 读 +0x8F |

### 建议替换
```
byte bPad_0x8E;          // +0x8E
bool bAutosaverEnabled;  // +0x8F
```

---

## WindowManager.pField_0x04 @ 0x04 (120B)

当前 layout: `byte[120] pField_0x04` (struct 136B)。decompiler 把 this+4 起标为 pField_0x04[i]; 下表 offset 相对 struct 基址。

### 拆分建议(绝对 offset)
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| 0x04 | 24 | header | listenerListHeader | ctor 清零后 `*(this+0x10)=this+0x08; *(this+0x14)=this+0x08`(侵入式 list 哨兵) |
| 0x1C | 56 | Mutex | mutex | ctor `Mutex::Mutex((Mutex*)(this+0x1C))`; dtor ~Mutex |
| 0x54 | 4 | float | flWidth | SetWindowed/Resize/Initialize: `*(float*)(this+0x54)=(float)width` |
| 0x58 | 4 | float | flHeight | 同路径 height |
| 0x5C | 4 | Renderer* | pRenderer | ctor 第一参 `WindowManager(Renderer*, cEventDispatcher*)`; Resize 写 renderer 宽高 |
| 0x60 | 4 | SDL_Window* | pSDLWindow | Initialize SDL_CreateWindow 存; dtor SDL_DestroyWindow |
| 0x64 | 4 | SDL_GLContext | pGLContext | Initialize SDL_GL_CreateContext 存; dtor SDL_GL_DeleteContext |
| 0x68 | 4 | cEventDispatcher<SystemEvent>* | pEventDispatcher | ctor 第三参; SetWindowed/SetFullscreen DispatchEvent |
| 0x6C | 12 | vector<vector<Resolution>> | vecDisplayResolutions | ctor `vector::resize(this+0x6C, numDisplays)`; 步长 0xc |
| 0x78 | 12 | vector<map<Resolution,vector<int>>> | vecDisplayModeMaps | ctor `resize(this+0x78, numDisplays)`; dtor ~vector |

### 尾部 flags(blob 边界外)
| offset | size | name | evidence |
|--------|------|------|----------|
| 0x84 | 1 | bIsFullscreen | Initialize/SetWindowed/SetFullscreen/HandleEvent 读写 |
| 0x85 | 1 | bFlag_0x85 | ctor=1 |
| 0x86 | 1 | bFlag_0x86 | ctor=1 |
| 0x87 | 1 | bPad | ctor=0 |

### 边界校正
当前 Ghidra 把 0x7C 起 12B 标为 pOCurrentModeFlags, 与 ctor resize(pField_0x04+0x74)(绝对 0x78)冲突。以代码为准:
- vector resolutions @ **绝对 0x6C**
- vector mode maps @ **绝对 0x78**
- flags 应从 **0x84** 起

证据函数: ctor @0x1d0662, dtor @0x1d0a4a, Initialize @0x1d0cd0, SetWindowed @0x1d109e, SetFullscreen @0x1d1226, Resize @0x1d0b42, HandleEvent @0x1d1464。

---

## DynamicShadowComponent.nField_0x18 @ 0x18 (5B 打包区)

对比 ShadowEntityComponent (27B): +0x10 flSizeX +0x14 flSizeY +0x18 bEnabled +0x19 bPristine +0x1A bFlags

### 拆分建议
| offset | size | type | name | evidence |
|--------|------|------|------|----------|
| 0x10 | 4 | float | flSizeX | ShadowEntityComponent::SetSize @0x71792 写, bFlags|=2 |
| 0x14 | 4 | float | flSizeY | 同上 bFlags|=4 |
| 0x18 | 1 | bool | bEnabled | Enable @0x717ce: bFlags ^= 1; Lua 转发 |
| 0x19 | 1 | byte | bPristine | Pool GetNew @0x9080e: obj+0x19=0 |
| 0x1A | 1 | byte | bFlags | Enable 翻转 bit0; SetSize 置 bit1/2 |
| 0x1B | 1 | byte | bPad_0x1B | 对齐 0x1C |

### 建议替换
```
float flSizeX;    // +0x10 (retype from nSizeX)
float flSizeY;    // +0x14 (retype from nSizeY)
bool  bEnabled;   // +0x18
byte  bPristine;  // +0x19
byte  bFlags;     // +0x1A
byte  bPad_0x1B;  // +0x1B
```

---

## 汇总

| Blob | 可拆? | 内部字段数 | 备注 |
|------|-------|------------|------|
| WaveComponent.pVec_0x64 (12B) | 可拆 | 3 | flWidth/flHeight/nNumWaves |
| cNetworkManager.wField_0x8E (2B) | 可拆 | 2 | bPad_0x8E + bAutosaverEnabled |
| WindowManager.pField_0x04 (120B) | 可拆 | ~11 | mutex/尺寸/SDL/GL/renderer/dispatcher/2×vector |
| DynamicShadowComponent.nField_0x18 (5B) | 可拆 | 3+pad | bEnabled/bPristine/bFlags |

**可拆 N = 4 / 需更多调查 M = 0**
