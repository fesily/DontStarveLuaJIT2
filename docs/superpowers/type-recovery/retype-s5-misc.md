# Phase 1 S5 Retype — 系统/杂项 void* 字段回写报告

> 输入: audit-s5-misc.md 的「确定」判定(12 个)
> 操作: ghidra-mcp modify_struct_field 写回 dontstarve_steam(macOS i386)
> 验证: 全部 9 个涉及 struct 的 get_struct_layout 复核 — 类型已变、size 未变、字段名保留
> 注: 两段式恢复同 S1-S4 — 先按字段名改类型(会清空字段名),再以 `field_name:"offset:0xN"` + new_name 重新落名。最终布局字段名与 audit 表一致。
> 注: 第 12 项 struct 名确认为 `SoundProjectManager`(64B, / 根类别);`cSoundProjectManager` 不存在(search_data_types 空),与 audit 表 alias 注记一致。

## 成功 (12/12)

| struct.field | 新类型 | 偏移 | 判定来源 |
|------|------|------|------|
| cApplication.pMSystemService | DontStarveSystemService * | 0x0 | 字段名语义; types_common 已定义 |
| cApplication.pMGameService | DontStarveGameService * | 0x4 | 字段名语义; types_common 已定义 |
| cApplication.pMGame | cGame * | 0x8 | pMGame→cGame*; types_common 已定义 |
| cBPWorld.pSimulation | cSimulation * | 0x30 | 字段名语义; types_common 已定义 |
| DontStarveGameService.pSystemService | DontStarveSystemService * | 0x4 | 字段名语义; header: void* pSystemService |
| HttpClient2.pCurlRequestManager | CurlRequestManager * | 0x0 | 证据 C2: this[0]=new CurlRequestManager() |
| SimThread.pSimulation | cSimulation * | 0x7c | 字段名语义; types_common 已定义 |
| SimThread.pStrResult | char * | 0x84 | pStr* 字符串指针命名 |
| PerfIndicator.pGame | cGame * | 0x0 | tier3-e: pGame=cGame*, ctor=param_2 |
| PerfPane.pGame | cGame * | 0x18 | tier3-e: pGame=cGame* |
| cMasterServerRequest.pMasterServer | cMasterServer * | 0xc | evidence: ctor=param_1 cMasterServer* |
| SoundProjectManager.pSoundSystem | cSoundSystem * | 0x3c | 字段名语义; types_common 已定义 |

## 失败清单

无(SKIP_NEED_TYPE: 0 / FAIL_SPACE: 0 / FAIL_FIELD: 0)

## 类型预检

写前 search_data_types 确认全部 6 个目标类型已存在于 dontstarve_steam(/ 根类别, 非仅 /Demangler 占位):
DontStarveSystemService(164B), DontStarveGameService(36B), cGame(304B), cSimulation(412B), CurlRequestManager(8B), cMasterServer(145B), cSoundSystem(56B);char 为内建。

## 抽查结果(9 struct, 全部 get_struct_layout 复核)

| struct | size(改前/改后) | 关键字段确认 |
|------|------|------|
| cApplication | 16 / 16 | pMSystemService=DontStarveSystemService*; pMGameService=DontStarveGameService*; pMGame=cGame* |
| cBPWorld | 52 / 52 | pSimulation=cSimulation*; pBroadphase 等 7 个「推断」未动 |
| DontStarveGameService | 36 / 36 | pSystemService=DontStarveSystemService* |
| HttpClient2 | 4 / 4 | pCurlRequestManager=CurlRequestManager* |
| SimThread | 140 / 140 | pSimulation=cSimulation*; pStrResult=char*; pLuaState(推断)未动 |
| PerfIndicator | 1048 / 1048 | pGame=cGame* |
| PerfPane | 64 / 64 | pGame=cGame*; vector 三件套(跳过)未动 |
| cMasterServerRequest | 16 / 16 | pMasterServer=cMasterServer* |
| SoundProjectManager | 64 / 64 | pSoundSystem=cSoundSystem* |

结论:12 个「确定」字段全部成功回写(0 失败、0 类型缺失);「推断(13)/待定(9)/跳过(69)」未触碰。已 save_program。
