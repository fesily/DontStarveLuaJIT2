# Blob Split B — GameLibConfig / cShardManager / ParticleEmitter / tServerListing

> program: `dontstarve_steam` (macOS i386)
> method: read-only ghidra-mcp (`get_struct_layout` + `decompile_function` + xrefs)
> generated: 2026-08-10
> note: 本报告只提供拆分建议与证据，未写回 Ghidra。

## 前提

- 本二进制 `std::string` 为 **GCC4 COW 旧 ABI = 4B**（仅 `_M_p` 数据指针）。
- `cNetID2` size = **44B (0x2C)**（`get_struct_layout` 确认）。
- `ProcessId` size = **4B**。
- `cEntityComponent` size = **16B**（vtable@0 + body@4..0xF）。

---

## GameLibConfig.pField_0x00 @ 0x00 (68B)

### 当前 blob

| parent field | abs | size | type |
|---|---:|---:|---|
| GameLibConfig.pField_0x00 | 0x00 | 68 | byte[68] |

### 拆分建议

| offset | size | type | name | evidence |
|---:|---:|---|---|---|
| 0x00 | 1 | bool | bEnableAudio | ctor@00019fcc `pField[0]=0`; Startup@000087ac WRITE; cGame@0000f6b9 READ（决定是否建 cSoundSystem） |
| 0x01 | 1 | bool | bField_01 | ctor `pField[1]=0`; Startup@000089b9 WRITE |
| 0x02 | 1 | bool | bField_02 | ctor `pField[2]=0` |
| 0x03 | 1 | bool | bField_03 | ctor `pField[3]=1` |
| 0x04 | 4 | int | nMaxPlayers | ctor 写 `0A 00 00 00`（decompile 显示 `[4]=10,[5..7]=0`）；默认 10 |
| 0x08 | 4 | int | nField_08 | ctor 清零 `[8..0xb]=0` |
| 0x0C | 4 | int | nField_0C | ctor 清零 `[0xc..0xf]=0` |
| 0x10 | 4 | int | nField_10 | ctor 清零 `[0x10..0x13]=0` |
| 0x14 | 44 | cNetID2 | netId | ctor `cNetID2::Clear(pField+0x14)`；内部 `+0x24/+0x28` 亦先清零（与 tServerListing 同模式） |
| 0x40 | 4 | ProcessId | processId | ctor `ProcessId::ProcessId(pField+0x40)` |

> 合计 1+1+1+1+4+4+4+4+44+4 = **68B**，无残留空洞。

### 使用方

- 全局单例 `_gGameLibConfig` @ 0x4653dc size=148；`__GLOBAL__I_a` @ 0001a386 构造。
- xrefs: Startup WRITE +0x00/+0x01；cGame READ +0x00；InitServer 间接读后续 string 区。

---

## GameLibConfig.pStrs @ 0x44 (32B)

### 当前 blob

| parent field | abs | size | type |
|---|---:|---:|---|
| GameLibConfig.pStrs | 0x44 | 32 | byte[32] |

### 拆分建议

| offset | abs | size | type | name | evidence |
|---:|---:|---:|---|---|---|
| 0x00 | 0x44 | 4 | std::string | str_0 | ctor `string(pStrs+0,"")`；dtor@00019dee 释放 |
| 0x04 | 0x48 | 4 | std::string | str_1 | ctor `string(pStrs+4,"")`；dtor 释放 |
| 0x08 | 0x4C | 4 | std::string | str_2 | ctor `string(pStrs+8,"")`；dtor 释放 |
| 0x0C | 0x50 | 4 | std::string | str_3 | ctor `string(pStrs+0xc,"")`；dtor 释放 |
| 0x10 | 0x54 | 4 | std::string | str_4 | ctor `string(pStrs+0x10,"")`；dtor 释放 |
| 0x14 | 0x58 | 4 | std::string | strGameName | ctor `string(pStrs+0x14,"DoNotStarveTogether")`；dtor 释放 |
| 0x18 | 0x5C | 4 | std::string | strBindAddress | ctor `string(pStrs+0x18,"")`；**InitServer@001693b9** 作为 `SocketDescriptor` 绑定地址读取 `*(GameLibConfig+0x5C)` |
| 0x1C | 0x60 | 4 | std::string | str_7 | ctor `string(pStrs+0x1c,"")`；dtor 释放 |

> 8×4B = **32B**。dtor 仅销毁这 8 个 string → 结构内堆成员仅此 8 个。
> 语义：`strGameName` / `strBindAddress` 已锁定；`str_0..str_4/str_7` 名称仍可后续对照命令行/配置解析再命名。

---

## GameLibConfig.pNetIds @ 0x64 (48B)

### 当前 blob

| parent field | abs | size | type |
|---|---:|---:|---|
| GameLibConfig.pNetIds | 0x64 | 48 | byte[48] |

### 拆分建议

| offset | abs | size | type | name | evidence |
|---:|---:|---:|---|---|---|
| 0x00 | 0x64 | 1 | bool | bField_64 | ctor `pNetIds[0]=0` |
| 0x01 | 0x65 | 3 | byte[3] | pad_65 | 对齐到 0x68；ctor 未单独写 |
| 0x04 | 0x68 | 44 | cNetID2 | netId2 | ctor `cNetID2::Clear(pNetIds+4)`；并预清 `pNetIds+0x28/+0x2c`（= cNetID2 内部 +0x24/+0x28） |

> 1+3+44 = **48B**。struct 总 size 0x94 = 148 与全局符号一致；**第二 cNetID2 起于 0x68 止于 0x94**，不是 0x8C/0x94 外延（纠正 remaining-b ≥0xC0 误估）。

### GameLibConfig 汇总（整对象）

| abs | size | type | name |
|---:|---:|---|---|
| 0x00 | 1 | bool | bEnableAudio |
| 0x01 | 1 | bool | bField_01 |
| 0x02 | 1 | bool | bField_02 |
| 0x03 | 1 | bool | bField_03 |
| 0x04 | 4 | int | nMaxPlayers |
| 0x08 | 4 | int | nField_08 |
| 0x0C | 4 | int | nField_0C |
| 0x10 | 4 | int | nField_10 |
| 0x14 | 44 | cNetID2 | netId |
| 0x40 | 4 | ProcessId | processId |
| 0x44 | 4 | std::string | str_0 |
| 0x48 | 4 | std::string | str_1 |
| 0x4C | 4 | std::string | str_2 |
| 0x50 | 4 | std::string | str_3 |
| 0x54 | 4 | std::string | str_4 |
| 0x58 | 4 | std::string | strGameName |
| 0x5C | 4 | std::string | strBindAddress |
| 0x60 | 4 | std::string | str_7 |
| 0x64 | 1 | bool | bField_64 |
| 0x65 | 3 | byte[3] | pad_65 |
| 0x68 | 44 | cNetID2 | netId2 |

**判定: 可拆**（3 个 blob 全部闭合，无 size 冲突）。

---

## cShardManager.pField_0x00 @ 0x00 (40B)

### 当前 blob

| parent field | abs | size | type |
|---|---:|---:|---|
| cShardManager.pField_0x00 | 0x00 | 40 | byte[40] |

### 拆分建议

| offset | size | type | name | evidence |
|---:|---:|---|---|---|
| 0x00 | 4 | void* | pVtable | ctor@001a2e44 `*(undefined***)pField = &PTR__cShardManager_0045719c`；dtor@001aada6 同样重写 |
| 0x04 | 4 | int | eShardType | ctor 清零；RegisterSlave 比较 `*(mInstance+4)==3` 才走 slave 注册（tier3-d §1） |
| 0x08 | 4 | int | nField_08 | ctor `pField[4..7]=0` |
| 0x0C | 4 | int | nField_0C | ctor `pField[0xc..0xf]=0` |
| 0x10 | 1 | byte | bField_10 | ctor `pField[0x10]=0`（仅 1B 写） |
| 0x11 | 3 | byte[3] | pad_11 | 对齐 string@0x14；ctor 未写 |
| 0x14 | 4 | std::string | strClusterName | ctor `*(pField+0x14)=empty`；dtor `_M_destroy(*(pField+0x14))` |
| 0x18 | 4 | uint | nShardId | ctor 清零；RegisterSlave 插入 json `"id"` ← `*(shardMgr+0x18)` |
| 0x1C | 4 | int | nField_1C | ctor 清零（`pField[0x18..0x23]` 12B 连清的一部分） |
| 0x20 | 4 | int | nField_20 | ctor 清零 |
| 0x24 | 4 | std::string | strWorldSession | ctor `*(pField+0x24)=empty`；dtor `_M_destroy(*(pField+0x24))` |

> 4×6 + 1+3 + 4×4 = **40B**。blob 尾恰接已拆字段 `pM_shardPlayers@0x28`（std::map 24B）。

### 使用方 / 邻接验证

- dtor 销毁顺序：pCheshireCat → pField_0xA0 虚删 → pShardBroadcast → list@0x90 → 3×map → **string@0x24 → string@0x14**。
- map 自引用头：`pM_shardPlayers` left/right = base+4（ctor），与 24B map 布局一致。

**判定: 可拆**。

---

## ParticleEmitter.pUNKNOWN_0x04 @ 0x04 (132B)

### 当前 blob

| parent field | abs | size | type |
|---|---:|---:|---|
| ParticleEmitter.pVtable | 0x00 | 4 | void* |
| ParticleEmitter.pUNKNOWN_0x04 | 0x04 | 132 | byte[132] |

> 总 size 136B。ctor@0005e1fc 先调 `cEntityComponent::cEntityComponent(this)` 再覆写 vtable `PTR__ParticleEmitter_004556d8`。

### 拆分建议（offset 相对 blob = abs−4）

| offset | abs | size | type | name | evidence |
|---:|---:|---:|---|---|---|
| 0x00 | 0x04 | 1 | byte | bAwakeFlag | cEntityComponent body；layout `bAwakeFlag@+1` 在基类 16B 内 |
| 0x01 | 0x05 | 3 | byte[3] | pad_05 | 基类 pad |
| 0x04 | 0x08 | 4 | void* | pVec_component | cEntityComponent@+8 |
| 0x08 | 0x0C | 4 | void* / cEntity* | pEntity | cEntityComponent@+0xC（Ghidra 现 -BAD-） |
| 0x0C | 0x10 | 4 | float | flMaxAge | ctor 写 `0x3f800000`（1.0f）于 pUNKNOWN+0xC；tier3-a §21 SetMaxAge |
| 0x10 | 0x14 | 4 | uint | nField_14 | ctor 清零 pUNKNOWN+0x10 |
| 0x14 | 0x18 | 4 | uint | nField_18 | ctor 清零 |
| 0x18 | 0x1C | 4 | uint | nField_1C | ctor 清零 |
| 0x1C | 0x20 | 4 | uint | nField_20 | ctor 清零 |
| 0x20 | 0x24 | 12 | Vector3 / float[3] | flAcceleration | ctor 从 `PTR_Zero` 拷 12B 到 pUNKNOWN+0x20；tier3-a SetAcceleration |
| 0x2C | 0x30 | 1 | byte | bRotation | ctor `pUNKNOWN[0x2c]=1` |
| 0x2D | 0x31 | 2 | byte[2] | pad_31 | ctor 清零 |
| 0x2F | 0x33 | 1 | bool | bParticleBufferFlag | SetMaxNumParticles@0005e5ba 传给 `ParticleBuffer::ParticleBuffer(..., bool)` |
| 0x30 | 0x34 | 1 | byte | bField_34 | ctor 清零 |
| 0x31 | 0x35 | 1 | byte | bHasRotationComponents | SetMaxNumParticles：若非 0 则 `ParticleBuffer::CreateRotationComponents` |
| 0x32 | 0x36 | 26 | byte[26] | UNKNOWN_36 | ctor 未写；**需更多调查**（可能含 UV/色/发射参数） |
| 0x4C | 0x50 | 8 | Vector2 / float[2] | flUVFrameSize | ctor 从 `PTR_One` 拷 8B 到 pUNKNOWN+0x4C |
| 0x54 | 0x58 | 4 | uint | nBlendMode | ctor `=3` |
| 0x58 | 0x5C | 4 | uint | nField_5C | ctor 0 |
| 0x5C | 0x60 | 4 | uint | nField_60 | ctor 0 |
| 0x60 | 0x64 | 4 | uint | dwTextureHandle | SetRenderResources@0005e668 `pUNKNOWN+0x60 = TextureManager::find`；assert `"mTexture"` |
| 0x64 | 0x68 | 4 | float | flUVHeight | SetRenderResources 写纹理 height |
| 0x68 | 0x6C | 4 | float | flUVWidth | SetRenderResources 写纹理 width |
| 0x6C | 0x70 | 4 | uint | dwEffectHandle | SetRenderResources `pUNKNOWN+0x6c = EffectManager::find`；assert `"mEffect"` |
| 0x70 | 0x74 | 4 | uint | nField_74 | ctor 0 |
| 0x74 | 0x78 | 4 | uint | nRenderLayer | ctor `=3`；tier3-a SetLayer |
| 0x78 | 0x7C | 4 | SceneGraphNode* / void* | pNode | dtor@0005e2d2 虚调 `(*vt+0x18)` 后置 0；ParticleBufferRenderer 挂接点 |
| 0x7C | 0x80 | 4 | ParticleBuffer* | pParticleBuffer | SetMaxNumParticles `new(0x28)`；dtor `~ParticleBuffer + delete` |
| 0x80 | 0x84 | 4 | uint | nMaxParticles | ctor `=0x20`(32)；SetMaxNumParticles 写入 |

> blob 0x00..0x83 = **132B** 封口；对象 abs 0x00..0x87 = 136B。

### 使用方

- dtor@0005e2d2：释放 pNode@blob+0x78、pParticleBuffer@blob+0x7c，再 `~cEntityComponent`。
- SetMaxNumParticles@0005e5ba：重分配 ParticleBuffer，读 bParticleBufferFlag / bHasRotationComponents。
- SetRenderResources@0005e668：写 texture/effect/UV；源路径字符串含 `ParticleEmitter.cpp`。

**判定: 可拆**（布局可落字段；中间 26B `UNKNOWN_36` 语义仍待查，不阻塞拆分）。

---

## tServerListing.pStrs @ 0x00 (52B)

### 当前 blob

| parent field | abs | size | type |
|---|---:|---:|---|
| tServerListing.pStrs | 0x00 | 52 | byte[52] |

### 拆分建议

| offset | size | type | name | evidence |
|---:|---:|---|---|---|
| 0x00 | 4 | std::string | strName | ctor@0019a630 写 empty×13；**WriteServerListingTable@00176dc6** `lua_setfield(...,"name")` ← `*param_3` |
| 0x04 | 4 | std::string | strIp | WSLT `"ip"` ← `param_3[1]` |
| 0x08 | 4 | std::string | strRow | WSLT `"row"` ← `param_3[2]` |
| 0x0C | 4 | std::string | strSession | WSLT `"session"` ← `param_3[3]` |
| 0x10 | 4 | std::string | strHost | WSLT 与 `cAccountManager::GetUserID` compare 判定 `"owner"` ← `param_3[4]`（host/userid） |
| 0x14 | 4 | std::string | strDescription | WSLT `"description"` ← `param_3[5]` |
| 0x18 | 4 | std::string | strTags | WSLT `"tags"` ← `param_3[6]` |
| 0x1C | 4 | std::string | strMode | WSLT `"mode"` ← `param_3[7]` |
| 0x20 | 4 | std::string | strGameData | WSLT `"game_data"` ← `param_3[8]` |
| 0x24 | 4 | std::string | strWorldGenData | WSLT `"world_gen_data"` ← `param_3[9]` |
| 0x28 | 4 | std::string | strPlayersData | WSLT `"players_data"` ← `param_3[10]` |
| 0x2C | 4 | std::string | strSeason | WSLT `"season"` ← `param_3[11]` |
| 0x30 | 4 | std::string | strIntention | WSLT `"intention"` ← `param_3[12]` |

> 13×4B = **52B**，无空洞。尾接已拆 `pListModsInfo@0x34`（std::list 8B 头，ctor 自引用）。

### 使用方

- ctor@0019a630：13×empty + list + ports/ping/version/3×cNetID2 + guid + 尾 string。
- WriteServerListingTable@00176dc6：上述 13 个 lua 字段一一对应。
- unknown-scan-s5 命名序列 name/ip/row/session/host/desc/tags/mode/data/worldgen/players/season/intent 与本表一致。

**判定: 可拆**。

---

## 汇总

| # | blob | size | 判定 | 备注 |
|---:|---|---:|---|---|
| 1a | GameLibConfig.pField_0x00 | 68 | **可拆** | 4×bool/flag + nMaxPlayers + 3×int + cNetID2 + ProcessId |
| 1b | GameLibConfig.pStrs | 32 | **可拆** | 8×std::string（含 DoNotStarveTogether / bind address） |
| 1c | GameLibConfig.pNetIds | 48 | **可拆** | bField + pad + cNetID2@+0x04 |
| 2 | cShardManager.pField_0x00 | 40 | **可拆** | pVtable + eShardType + ints + 2×string + nShardId |
| 3 | ParticleEmitter.pUNKNOWN_0x04 | 132 | **可拆** | 基类 tail + 发射/渲染状态；26B UNKNOWN_36 语义待查 |
| 4 | tServerListing.pStrs | 52 | **可拆** | 13×std::string，WSLT 全命名 |

### 计数

- **可拆 N = 6**（含 GameLibConfig 3 子 blob）
- **需更多调查 M = 1**（ParticleEmitter 中段 26B `UNKNOWN_36` 字段语义；不阻塞布局拆分）

### 回写注意

1. GameLibConfig 总 size 保持 **148 (0x94)**；勿按 remaining-b 的 ≥0xC0 扩。
2. tServerListing 当前 Ghidra size **266**，文档/ctor 写到 **0x10C=268**——`wField_0x108` 可能被截断，拆 pStrs 时建议同步核对尾字段（本任务范围外）。
3. ParticleEmitter 拆分时建议同时把 `cEntityComponent` 基类字段从 blob 头拆出（0x04..0x0F），与 VFXEffectEmitter 对称。
4. 全部建议仅供重建 struct；本文件为只读调查产物。
