# Retype Blob B — 拆分回写报告

> program: `dontstarve_steam` (macOS i386)
> method: delete_data_type + create_struct 全量重建
> generated: 2026-08-10
> evidence: blob-split-a.md / blob-split-b.md / blob-split-c.md

## 汇总

| # | struct | 重建前 size | 重建后 size | 字段数 | 结果 |
|---:|---|---:|---:|---:|---|
| 1 | GameLibConfig | 148 | 148 | 21 | 3 blob 全拆 |
| 2 | cShardManager | 168 (0xA8) | 168 | 27 | pField_0x00 拆 11 字段 |
| 3 | ParticleEmitter | 136 | 136 | 30 | pUNKNOWN_0x04 全拆（含 cEntityComponent 基类尾） |
| 4 | tServerListing | 266 | 266 | 37 | pStrs 拆 13×cStdString |
| 5 | TDataCacheParticleBufferRenderer | 108 | 108 | 12 | pUNKNOWN_0x48 拆 9 字段 |
| 6 | TDataCacheVideoNode | 124 | 124 | 16 | pUNKNOWN_0x48 拆 12 字段 + pad |
| 7 | ImageNode | 260 | 260 | 23 | pUNKNOWN_0x94 拆 22 字段 |
| 8 | TDataCacheRoadManagerNode | 112 | 112 | 13 | pUNKNOWN_0x48 拆 9 字段 + 尾 pad |
| 9 | WindowManager | 136 | 136 | 15 | pField_0x04 全拆 + 边界校正 |

**重建 N = 9 / 失败 K = 0 / 新类型建 M = 0**（全部子类型已存在）

## 逐 struct 明细

### 1. GameLibConfig (148B, 21 字段)
- `pField_0x00` (68B) → `fEnableAudio/fField_01/fField_02/fField_03` (bool×4) + `nMaxPlayers` + `nField_08/0C/10` + `netId` (cNetID2 44B) + `processId` (ProcessId 4B)
- `pStrs` (32B) → `str_0..str_4/strGameName/strBindAddress/str_7` (8×cStdString 4B)
- `pNetIds` (48B) → `fField_64` + `pPad_65[3]` + `netId2` (cNetID2@0x68)
- size 148 不变；netId2 起于 0x68 止于 0x94（纠正 ≥0xC0 误估）

### 2. cShardManager (168B, 27 字段)
- `pField_0x00` (40B) → `pVtable` + `nEShardType` + `nField_08/0C` + `bField_10` + `pPad_11[3]` + `strClusterName` (cStdString) + `dwShardId` + `nField_1C/20` + `strWorldSession` (cStdString)
- 其余 17 字段（maps/timers/cheshire/broadcast 等）原样保留

### 3. ParticleEmitter (136B, 30 字段)
- `pUNKNOWN_0x04` (132B) 全拆：
  - cEntityComponent 基类尾：`bAwakeFlag` + `pPad_05[3]` + `pVec_component` + `pEntity`（0x04..0x0F）
  - `flMaxAge` + `dwField_14/18/1C/20` + `pAcceleration` (float[3]) + `bRotation` + `pPad_31[2]` + `fParticleBufferFlag` + `bField_34` + `bHasRotationComponents`
  - `pUNKNOWN_36` (26B，语义待查，不阻塞) + `pUVFrameSize` (float[2]) + `dwBlendMode` + `dwField_5C/60` + `dwTextureHandle` + `flUVHeight/Width` + `dwEffectHandle` + `dwField_74` + `dwRenderLayer` + `pNode` + `pParticleBuffer` (ParticleBuffer*) + `dwMaxParticles`

### 4. tServerListing (266B, 37 字段)
- `pStrs` (52B) → 13×cStdString：`strName/strIp/strRow/strSession/strHost/strDescription/strTags/strMode/strGameData/strWorldGenData/strPlayersData/strSeason/strIntention`
- 其余 24 字段原样保留（含 3×cNetID2、ports、guid 等）
- 注：wField_0x108 截断问题（文档 0x10C vs Ghidra 266）未在本任务范围内处理，保持现状

### 5. TDataCacheParticleBufferRenderer (108B, 12 字段)
- `pUNKNOWN_0x48` (36B) → `dwField_48` + `pEmitter` (ParticleEmitter*) + `dwField_50` + `dwNumVerts` + `pData0..pData4` (void*×5)

### 6. TDataCacheVideoNode (124B, 16 字段)
- `pUNKNOWN_0x48` (52B) → `nHAnchor` + `nVAnchor` + `pSizeXY` (float[2]) + `dwEffectHandle` + `dwTint` + `nFrameW/H` + `pFramePixels` + `dwTexY/U/V` + `fUseTransTex` + `pPad_0x79[3]`

### 7. ImageNode (260B, 23 字段)
- `pUNKNOWN_0x94` (112B) → 22 字段：`nMaxLines/nField_98` (=-1) + `dwField_9C` + `dwBlendMode` + `dwTextureHandle/dwTextureHandle2/dwField_AC` (AtlasManager) + `pSize` (float[2]) + `dwField_B8/BC` + `dwTint` + `flAlphaMax/Min` + `flField_CC` + `pVOffset` (float[3]) + `dwField_DC` + `flField_E0` + `pVEffectParams` (float[2]) + `pVField_EC` (byte[8]) + `fDepthTest/fDepthWrite` + `pVField_F8` (float[3])
- **校正**：证据中 `nField_100` 实为 ctor 对 0xF8 的 8B+4B 两次拷贝（`PTR_Zero`），即 `vField_F8` 12B 整体；已合并，字段数 23 而非 24

### 8. TDataCacheRoadManagerNode (112B, 13 字段)
- `pUNKNOWN_0x48` (40B) → `pStripData_begin/end/cap` + `dwVertDescHandle` + `pField_58[4]` + `pAABB_begin/end/cap` + `pRenderer` (GameRenderer*)
- **补充**：证据仅列 36B，blob 40B 尾部 4B 补 `pField_0x6C[4]` 以保持 size 112

### 9. WindowManager (136B, 15 字段)
- `pField_0x04` (120B) → `pListenerListHeader` (24B) + `mutex` (Mutex 56B) + `flWidth/flHeight` + `pRenderer` (Renderer*) + `pSDLWindow/pGLContext/pEventDispatcher` (void*) + `pVecDisplayResolutions` (12B) + `pVecDisplayModeMaps` (12B)
- **边界校正**：vector@0x6C/0x78（原 pOCurrentModeFlags@0x7C 冲突，按 ctor resize 代码重建）；flags 从 0x84 起：`fIsFullscreen/fFlag_0x85/fFlag_0x86/bPad`
- 原 0x7C..0x87 的 pOCurrentModeFlags[12] 已移除

## 验证

- 9 struct 全部 `get_struct_layout` 复核：size 与重建前一致，字段偏移/类型符合证据
- 每 2-3 个 struct 后 `save_program`；最终 save_program 完成
- 子类型全部已存在：cNetID2(44)/ProcessId(4)/Mutex(56)/cStdString(4)/cEntityComponent(16)/ParticleBuffer(32)/Renderer(564)/VideoNode(276)/GameRenderer(2024)/ParticleBufferRenderer(160)/Timer/tCheshireCat_Shard/cShardBroadcast
- Vector2/Vector3 未定义，按证据用 float[2]/float[3] 等价表示

## 遗留

- ParticleEmitter `pUNKNOWN_36` (26B) 语义待查（不阻塞）
- tServerListing 尾字段 `wField_0x108` 截断核对（范围外）
- ImageNode `pSgn` (148B) 头 blob 未拆（范围外，属另一拆分任务）
