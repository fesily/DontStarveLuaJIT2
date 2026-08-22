# Review Slice 18 — GoogleAnalyticsCookie / GoogleAnalyticsGenerator / MemoryCache / CacheItem

> 审查方式:Ghidra `get_struct_layout` 读取回写结构 → 与 `types_common.h` + `tier3-e-system.md` 比对 → idalib-mcp(会话 f9cdc808)decompile 交叉验证字段偏移。
> 本分片 IDA decompile 用量:GoogleAnalyticsCookie 2 次(ctor 0x12E812、dtor 0x12E65E)、GoogleAnalyticsGenerator 1 次(ctor 0x12C1D4)、MemoryCache 2 次(ctor 0x23D34、Cache 0x23E06)、CacheItem 共享 Cache 0x23E06 1 次。均在每类型 ≤2 限制内。
> 只读审查,未做任何回写。

## 结论摘要

4 个类型全部 PASS。Ghidra 回写结构与 tier3-e 报告及 types_common.h 完全一致(偏移/大小/类型全命中),IDA 反编译独立证实各关键偏移。唯一注意点:GoogleAnalyticsCookie 文档中"vtable @ 0x450998"实为 Ghidra 的 PTR 符号名,实际写入对象的 vtable 指针值是 0x462544(见下),属文档表述精度问题,不影响结构布局。

---

### GoogleAnalyticsCookie
- 状态: **PASS**(1 条文档表述注意点)
- Ghidra 大小: 24B | 文档大小: 24B (0x18) | 匹配: yes
- 字段比对: 无差异。Ghidra 字段 pVtable@0(void*)、pM_strValue@4(byte[4])、pM_strName@8(byte[4])、pM_args_begin/end/cap@0xC/0x10/0x14 —— 与文档 `{ void* pVtable; uint8_t m_strValue[4]; uint8_t m_strName[4]; void* m_args[3]; }` 偏移、大小、类型一一对应(m_args 展开为 vector 三指针);仅命名前缀 pM_/m_ 不同,无实质差异。
- 证据:
  - IDA ctor 0x12E812:`*a1 = &unk_462544`;`std::string::string(a1+1)`(@4 m_strValue)、`std::string::string(a1+2)`(@8 m_strName)、`a1[3]=a1[4]=a1[5]=0` + `vector<string>::push_back(a1+3)`(@0xC vector)。
  - IDA dtor 0x12E65E:`~vector(thisa+12)` 后按序释放 `thisa+2`(m_strName@8)与 `thisa+1`(m_strValue@4)——与字段顺序一致。
  - Ghidra ctor 0x12E77E:与 IDA 相同布局。
- 问题清单:
  - **注意点(非布局错误)**:tier3-e 文档写 "vtable @ 0x450998"。实测 0x450998 是全局 PTR 变量,其值 = 0x46253C(读内存 0x450998 首字节 `3c254600`);ctor/dtor 写入 `PTR_vtable_00450998 + 8` = 0x462544,与 IDA `&unk_462544` 完全一致。0x462544 处为真实虚函数指针表(0x12E5D0、0x12E74A)。建议后续把文档 vtable 地址改为 0x462544 或注明 PTR 符号语义。

### GoogleAnalyticsGenerator
- 状态: **PASS**
- Ghidra 大小: 32B | 文档大小: 32B (0x20) | 匹配: yes
- 字段比对: 无差异。Ghidra: dwField_0@0(uint)、pM_strReportName@4(byte[4])、nM_settings_pad@8、nM_settings_color@0xC、pM_settings_parent@0x10、pM_settings_left@0x14、pM_settings_right@0x18、nM_settings_count@0x1C —— 与文档 `{ uint32_t nField_0; uint8_t m_strReportName[4]; int32_t m_settings[6]; }` 一致;文档 m_settings[6] 即 24B map 头,回写展开为 6 个命名字段,偏移全对。
- 证据:IDA ctor 0x12C1D4:`*(_DWORD*)thisa = 0`(nField_0@0);`std::string::string(this, thisa+4, "DontStarve.html")`(m_strReportName@4);map@+8 初始化:color@0xC=0、parent@0x10=0、left@0x14=&this+0xC、right@0x18=&this+0xC、count@0x1C=0 —— 标准 24B _Rb_tree 头(left/right 自引用 &header),与 Ghidra 布局逐字段吻合。无 vtable 写入,符合文档"无 vtable"。
- 问题清单: 无。

### MemoryCache
- 状态: **PASS**
- Ghidra 大小: 24B | 文档大小: 24B (0x18) | 匹配: yes
- 字段比对: 无差异。Ghidra: nM_cache_pad@0(int)、nM_cache_color@4、pM_cache_parent@8、pM_cache_left@0xC、pM_cache_right@0x10、nM_cache_count@0x14 —— 文档 `{ int32_t m_cache[6]; }` 即 24B map 头,回写展开一致。
- 证据:IDA ctor 0x23D34:parent@8=0、color@4=0、right@0x10=0、left@0xC=0、count@0x14=0,随后 `left@0xC = this+4`、`right@0x10 = this+4`(哨兵自引用)—— 与 Ghidra 布局逐字段吻合。IDA Cache 0x23E06:`_Rb_tree::find(thisa)`、end 比较 `(char*)thisa+4`(header 地址)—— 证实 map 基 @0、header @+4、count @0x14。无 vtable,符合文档。
- 问题清单: 无。

### CacheItem
- 状态: **PASS**
- Ghidra 大小: 272B | 文档大小: 272B (0x110) | 匹配: yes
- 字段比对: 无差异。Ghidra: nCrc32@0(int)、dwSize@4(uint)、bSynchronized@8(byte)、pName@9(char[259])、pData@0x10C(void*) —— 文档 `{ int32_t nCrc32; uint32_t nSize; uint8_t bSynchronized; char szName[259]; void* pData; }` 完全一致(9+259=268=0x10C ✓);仅 nSize/dwSize、szName/pName 命名差异。
- 证据:IDA Cache 0x23E06(本地 CacheItem 构造):`v16[0]=crc32`、`v16[1]=__n`(nSize)、`LOBYTE(v16[2])=a6`(bSynchronized@8)、`strncpy((char*)&v16[2]+1, name, 0xFF)`(szName@9,拷贝上限 0xFF)、`v16[67]=operator new[](n)`(v16 为 _DWORD[68],67×4=268=0x10C pData)、`memcpy(v15, v16, 272)`(sizeof(v15)=272 证实 0x110)。
  - 更新路径 `v9[6]=crc32`、`v9[7]=__n`、`*((_BYTE*)v9+32)=a6`、`v9[73]=pData`:node 基 16B + key(cHashedString 8B)@+0x10 + CacheItem@+0x18 → 节点内 v9[6]=+0x18=nCrc32、v9[7]=+0x1C=nSize、byte[+0x20]=bSynchronized、v9[73]=+0x124=节点内 CacheItem.pData —— 与 tier3-e"节点内值 @ node+0x18、pData 绝对偏移 +0x124"吻合。
- 问题清单: 无。

---

## 汇总表

| 类型名 | 状态 | 主要问题 |
|---|---|---|
| GoogleAnalyticsCookie | PASS | 布局全对;文档 vtable 地址 0x450998 实为 PTR 符号(值 0x46253C),真实写入值 0x462544 = 0x450998 处指针+8,建议文档注明 |
| GoogleAnalyticsGenerator | PASS | 无 |
| MemoryCache | PASS | 无 |
| CacheItem | PASS | 无 |
