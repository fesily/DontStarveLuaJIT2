# Slice 10 Review — cAccountManager / cTwitchManager / LuaHttpQuery / CurlRequest

- 日期: 2026-08-08
- 审查者: Review10
- 方法: ghidra-mcp `get_struct_layout` + idalib-mcp `decompile`(cAccountManager ctor 0x146ff6、LuaHttpQuery dtor 0xacb8)+ Ghidra `decompile_function` 补充(cTwitchManager ctor 0xb9f8c、CurlRequest ctor 0x1bb536)+ `read_memory` 验证 vtable
- 对照基准: `docs/superpowers/type-recovery/tier3-d-network.md` + `docs/superpowers/../../3rd/dst/game_decompiler/types_common.h`
- 只读审查,无任何写入

---

### cAccountManager
- 状态: PASS
- Ghidra 大小: 80B | 文档大小: 80B (0x50) | 匹配: yes
- 字段比对: 无实质不一致。全部 18 个字段名称/偏移/类型一一对应:
  - 0x00 pVtable(void*) / 0x04 bField_0x04(byte) / 0x08 pStr_0x08(byte[4],=std::string) / 0x0C pTAuthenticated(byte[16],=tAuthenticated 子结构) / 0x1C pM_authToken / 0x20 pM_username / 0x24 pStr_0x24 / 0x28 pStr_0x28 / 0x2C pStr_0x2C / 0x30 nField_0x30(int) / 0x34 pStr_0x34 / 0x38 pCommunication(void*) / 0x3C nField_0x3C(int) / 0x40 bField_0x40(byte) / 0x41 pPad_0x41(byte[3]) / 0x44 pStr_0x44 / 0x48 pStr_0x48 / 0x4C pM_offlineUserId
  - 仅命名风格差异:Ghidra 用 `p/dw/n` 匈牙利前缀(pStr_0x08 vs str_0x08),非布局问题
- 证据: idalib decompile ctor 0x146ff6 — 逐字段验证:vtable = off_456DFC;+0x04=0;string@+0x08;tAuthenticated ctor@+0x0C;+0x1C = _S_empty_rep_storage+12(authToken 空串);string@+0x20/0x24/0x28/0x2C;+0x30=0;+0x34=空串;+0x38 = `new(0x11C)` + cSteamAccountCommunication ctor 后回存(pCommunication);+0x3C=0;+0x40=1;+0x41..0x43=0;+0x44/+0x48=空串;+0x4C m_offlineUserId = "OU_" + SteamUser id append。与文档证据完全一致
- 问题清单: 无布局问题。子类型 `cAccountManager::tAuthenticated` 在 Ghidra 仅存 1B 占位(/Demangler/cAccountManager/tAuthenticated),主结构字段以原始 byte[16] 表示,未引用子类型 — 与文档"字段名低置信"处理一致,可接受

### cTwitchManager
- 状态: PASS
- Ghidra 大小: 40B | 文档大小: 40B (0x28) | 匹配: yes
- 字段比对: 无实质不一致:
  - 0x00 pVtable / 0x04 pCheshireCat(void*) / 0x08 nTVInitialized(int,文档名 bTVInitialized,类型同为 int) / 0x0C Timer(8B) / 0x14 bDeferredInit(byte) / 0x18 pM_username / 0x1C bField_0x1C(byte) / 0x20 nField_0x20(int) / 0x24 pM_channelName
- 证据: Ghidra decompile ctor 0xb9f8c — vtable = PTR__cTwitchManager_004562f8;+0x04 初 0 后 `new(0x588)` 构造 tCheshireCat;+0x08=0;Timer ctor@+0x0C;+0x14=0;string@+0x18;+0x1C=1;+0x20=0;string@+0x24;末尾 `if (bDeferredInit) DeferredInitialize()`,与文档证据 G 0xba1bc 一致。tCheshireCat 内 TwitchAuthThread 子对象 @ +0x4C0(ctor 中 `puVar1+0x130` dword = 0x4C0)、6 个 Chat*Callback @ +0x4A4..+0x4BC(ctor 中 puVar1[0x129..0x12e] ×4),与文档吻合
- 问题清单: 无

### LuaHttpQuery
- 状态: PASS
- Ghidra 大小: 32B | 文档大小: 32B (0x20) | 匹配: yes
- 字段比对: 一致:
  - 0x00 pVtable / 0x04 pM_requests(byte[20],=std::map<unsigned long, RequestInfo> 头部) / 0x18 dwM_pendingCount(uint) / 0x1C dwM_requestCounter(ulong)
- 证据: idalib decompile dtor 0xacb8 — vtable = unk_45D9E8;`_Rb_tree::_M_erase(this+4, *(this+0xC))`(map 头在 +4,根节点指针取 map 头 +8 → this+0xC),与文档 `_M_erase(this+4, *(this+0xC))` 逐字一致。vtable 内容 read_memory 0x45D9E8 = `[0xacb8(D1), 0xace6(D0), 0, 0]`,与文档一致(Ghidra 反编译符号 PTR_vtable_00450060+8 仅为标签别名,实际写址 0x45D9E8)
- 问题清单: 无。`LuaHttpQuery::RequestInfo`(8B)未建成独立 struct,仅出现在 std 模板参数中,主结构 map 字段以 byte[20] 表示 — 布局正确,子类型完整性为已知缺口

### CurlRequest
- 状态: PASS
- Ghidra 大小: 54B | 文档大小: ~54B (≥0x36) | 匹配: yes
- 字段比对: 一致:
  - 0x00 dwM_id(uint) / 0x04 pM_url / 0x08 pM_postData / 0x0C pM_authToken(uint[2],=uint64) / 0x14 dwField_0x14(uint) / 0x18 wField_0x18(ushort) / 0x1C pCurlMulti(void*) / 0x20 pCurlEasy(void*) / 0x24 pCurlSlist(void*) / 0x28 wField_0x28(ushort) / 0x2A bField_0x2A(byte) / 0x2C pM_response / 0x30 dwField_0x30(uint) / 0x34 wField_0x34(ushort)
- 证据: Ghidra decompile ctor 0x1bb536 — m_id=param_1;string m_url 自 HttpRequest2+0;m_postData 自 HttpRequest2+4;wField_0x18=*(req+0x14);dwField_0x14=*(req+0x10);m_authToken(8B)=*(req+8);pCurlMulti=param_3;pCurlSlist/pCurlEasy=0;bField_0x2A=0;wField_0x28=0;m_response=空串;pCurlEasy 由 SetupCurlHandle 0x1bb68c 设置。与文档字段表全部吻合
- 问题清单: 无

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| cAccountManager | PASS | 无;tAuthenticated 子类型仅 1B 占位(可接受) |
| cTwitchManager | PASS | 无 |
| LuaHttpQuery | PASS | 无;RequestInfo 未建独立 struct(已知缺口) |
| CurlRequest | PASS | 无 |

## 备注

1. idalib-mcp 会话 f9cdc808 直接调用报 "Session not found",但 `server_health`(database 参数)可达且 hexrays_ready=true — 会话 ID 校验宽松,decompile 均成功。跨验证用 idalib 完成 2 次(cAccountManager ctor、LuaHttpQuery dtor),其余 2 个 ctor 用 Ghidra decompile 补充,均未超过每类型 ≤2 次限制。
2. 4 个类型均为纯布局重建,无 padding 错位、无偏移漂移;std::string 按 4B 旧 ABI 与容器头(20B map/_Rb_tree、8B Timer)处理正确。
3. 唯一系统性差异为 Ghidra 回写字段名的匈牙利前缀风格(pM_/dwM_/wField_ 等)与文档 m_/n_/str_ 风格不同 — 不影响偏移与类型,属命名约定,建议后续回写统一,但不构成布局问题。
