# Tier 3 剩余类型恢复 — 分片 C: 文件系统 (KleiFile 族)

> 二进制:`dontstarve_steam`(macOS i386 32位, base 0x1000, gcc, Mach-O)
> 日期:2026-08-08;方法:ghidra-mcp(get_struct_layout / decompile_function)+ idalib-mcp(会话 c1f3f184, func_query / decompile)
> 约定:std::string = 4B 旧 ABI;std::_Rb_tree 头 = 24B;cHashedString = 8B(hash@0 + const char*@4)
> 范围:纯只读调查,未回写 Ghidra;所有回写建议见文末汇总表
> IDA decompile 预算:每类型 ≤2 次,已遵守(KleiFile 全局 2 次、FileHandle 2 次、ZipFS 2 次、LocalFS 2 次、MemoryCache 1 次、DLCMount 2 次、DirectoryUtils 1 次、cReader 1 次、BinaryBufferReader 2 次、BinaryBufferWriter 2 次、Growable 系列各 ≤2 次;其余用 ghidra decompile 交叉验证)

---

## 现状盘点(Ghidra 已定义)

| 类型 | Ghidra 现状 | 说明 |
|---|---|---|
| cReader | `/cReader` 20B,字段齐全 | 已存在 |
| cWriter | `/cWriter` 16B,字段齐全 | 已存在 |
| KleiFile | `/KleiFile` 1B 占位 | 待恢复(实际为静态函数模块) |
| FileUtil | `/FileUtil` 1B 占位 | 静态工具类 |
| KleiFile::FileHandle | `/Demangler/KleiFile/FileHandle` 1B | 待恢复 |
| KleiFile::LocalFileSystem | 1B | 待恢复 |
| KleiFile::ZipFileSystem | 1B | 待恢复 |
| KleiFile::MemoryCache | 1B(另有 `/MemoryCache` 24B,是 std::map 头,名字撞车) | 待恢复 |
| KleiFile::FileSystem | 1B | 待恢复(抽象基类) |
| KleiFile::DLCMount | 1B | 待恢复 |
| KleiFile::InitParams | 1B | 待恢复 |
| DirectoryUtils | 无(静态);`tFileDetails` 1B | tFileDetails 待恢复 |
| BinaryBufferReader | 1B | 待恢复 |
| BinaryBufferWriter | 1B | 待恢复 |
| GrowableBinaryBufferWriter | 1B | 待恢复 |
| EndianSwappedBinaryBufferReader | 1B | 待恢复 |
| GrowableEndianSwappedBinaryBufferWriter | 1B | 待恢复 |

---

## KleiFile(模块命名空间)

- 状态: 跳过(静态函数模块,无实例布局)
- 大小: 不适用(全局静态数据 @ 0x474e8d–0x474ea0)
- 字段: —

  | 全局 | 地址 | 类型 |
  |---|---|---|
  | sInitialized | 0x474e8d | byte |
  | sFileSystems | 0x474e90 | std::list<FileSystem*> 头(8B,自环) |
  | sHandlePool | 0x474e94 | Pool<FileHandle,FakeLock>* (Pool 本体 0x24B,见下) |
  | sOpenHandles | 0x474e98 | std::vector<FileHandle*>(12B) |
  | sMountedDLC | 0x474e9c | std::list<DLCMount> 头(8B,自环) |
  | sMemCache | 0x474ea0 | KleiFile::MemoryCache* |
  | sHandleMutex | (另址) | Mutex(见 types_common.h) |

- 证据:
  - `KleiFile::Init` 0x26c5cb:建 sFileSystems 自环 list → `Pool(v2, InitParams[1])` → 建 vector 并 `reserve(InitParams[1])` → 建 sMountedDLC 自环 list → 若 `InitParams[0]≠0` 则 `new(0x14)` 建 sMemCache(`v[0]=v[1]=max, v[2..4]=0`)
  - `KleiFile::Quit` 0x26c6e0(反汇编链);`Mount` 0x26c8a0 / `Unmount` 0x26c91c / `RegisterMount` 0x26c9a4 / `Load` 0x26ce47 / `Write` 0x26cf81 / `OpenRead` 0x26d27c / `Close` 0x26d42f 等全套 API
  - 调用点:`cApplication::Startup` 0x99ea 内 `KleiFile::Init((InitParams*)&local)`;随后 `new(0x114) → LocalFileSystem ctor → KleiFile::Mount((FileSystem*),"DEV",false)`
- 回写建议: 跳过(KleiFile 本身无 class 布局;其 6 个静态全局可在后续全局标注阶段处理,不建议建 1B struct)

### KleiFile::InitParams

- 状态: 待恢复
- 大小: 8B
- 字段:

  | 偏移 | 名称 | 类型 |
  |---|---|---|
  | 0x00 | nMemCacheSize | int32(0x1400000 = 20MB) |
  | 0x04 | nHandlePoolCount | int32(0x80 = 128) |

- 证据: `cApplication::Startup`(ghidra decompile @ 0x99ea):`local_190 = 0x1400000; local_18c = 0x80; KleiFile::Init((InitParams*)&local_190)`;`KleiFile::Init` 0x26c5cb 用 `*a1` 作 sMemCache 上限、`a1[1]` 作 Pool/vector 容量
- 回写建议: 新建(8B)

---

## KleiFile::FileHandle

- 状态: 待恢复
- 大小: 0x158 = 344B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | mOp | int32 | ctor 初值 5;Initialize 置为 Op 参数 |
  | 0x004 | mStatus | int32 | GetStatus 返回;1/2=进行中,3=完成,4=Freed,5=Deleted |
  | 0x008 | mNumRefs | int32 | AddRef 0x26a960 / DecRef 0x26a930;Free 断言 `0 == mNumRefs` |
  | 0x00C | m_path | char[256] | Initialize bzero 后 strncpy 0xFF |
  | 0x10C | m_pathHash | cHashedString | ctor 置 mEmptyString;Initialize 用 cHashedString::Set |
  | 0x114 | mMode | int32 | Initialize 第 2 参(Mode) |
  | 0x118 | nField_0x118 | int32 | 0 |
  | 0x11C | m_nSize | int32 | GetSize 0x26d938 返回;MemoryCache 缓存计费用 |
  | 0x120 | m_nBytesRead | int32 | GetBytesRead 0x26d99e 返回 |
  | 0x124 | m_pData | void* | 数据缓冲;Free 中 `pData && bHasData` 时 delete |
  | 0x128 | nField_0x128 | int32 | 0 |
  | 0x12C | nField_0x12C | int32 | 0 |
  | 0x130 | nField_0x130 | int32 | 0 |
  | 0x134 | nField_0x134 | int32 | 0 |
  | 0x138 | mResultHandler | void*[3] | 12B 小 list:MemCache 置 `+138=sMemCache,+13C=PTR_Cache_00450c44,+140=0` |
  | 0x144 | nField_0x144 | int32 | 0 |
  | 0x148 | nField_0x148 | int32 | 0 |
  | 0x14C | nField_0x14C | int32 | 0 |
  | 0x150 | bHasData | byte | Free 置 0;与 m_pData 配合释放 |
  | 0x154 | semaphore | Semaphore(4B) | dtor 显式 `Semaphore::~Semaphore(this+0x154)` |

- 证据:
  - ctor 0x26a514 / 0x26a436:置 0/4/8=5/0/0,0x10C=mEmptyString,0x114..0x14C=0,0x150=0,末尾 Semaphore ctor
  - Initialize 0x26a5f2:`Free()` 后 `+0=Op参数, +8=1, +0x114=Mode参数, bzero(+0xC,256), Set(+0x10C)`
  - Free 0x26a6d2(ghidra):断言 +8==0;+4=4,+8=0;清 0x10C/0x110/0x11C/0x120/0x124/0x128/0x12C/0x130/0x134/0x144/0x148/0x14C;`pData(0x124) && bHasData(0x150)` → delete
  - dtor 0x26a8d0(ghidra):DecRef(+8)→Free;+4=5;`Semaphore::~Semaphore(this+0x154)`
  - 大小闭环:`Pool::sChunk::sChunk` 0x26e172(ghidra)`operator_new(count * 0x158)` → sizeof(FileHandle)=0x158
  - GetSize 0x26d938 → +0x11C;GetBytesRead 0x26d99e → +0x120;GetStatus 0x26d86f → +4;MemCache 0x26d758 → +0x138/0x13C/0x140
- 回写建议: 重建(0x158 = 344B,替换 1B 占位;Pool<KleiFile::FileHandle,FakeLock> 与 vector<FileHandle*> 随之受益)

---

## KleiFile::FileSystem(抽象基类)

- 状态: 待恢复
- 大小: 0x110 = 272B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | pVtable | void* | 虚接口(LocalFS=unk_45BA88, ZipFS=unk_45B9F8) |
  | 0x004 | m_strMountName | cHashedString(8B) | Mount 时 Set;ctor 置 mEmptyString |
  | 0x00C | m_szMountPath | char[256] | strncpy 0xFF |
  | 0x10C | bMounted | byte | Mount 成功置 1 |

- 证据(派生类 ctor 反推基类布局):
  - `LocalFileSystem::LocalFileSystem` 0x271442 / `ZipFileSystem::ZipFileSystem` 0x26a9e6:共同前缀 `+4=0,+8=mEmptyString,+12b=0,+0x10C=0, vtable@0`(分别 45BA88 / 45B9F8)
  - `ZipFileSystem::Mount` 0x26aad4:`*(cHashedString*)(this+4)=v12; strncpy(this+12,src,0xFF); *(byte*)(this+0x10C)=1`
  - 虚方法(两派生类 override 一致):Mount/Exists/Load/Write/OpenRead/Tell/GetS/Read/Seek/Close/OpenWrite/IsAvailable/MountZip/UnmountZip
- 回写建议: 新建(抽象基类,仅布局,无 ctor;供 LocalFS/ZipFS 继承)

---

## KleiFile::LocalFileSystem

- 状态: 待恢复
- 大小: 0x114 = 276B(cApplication::Startup 0x99ea 处 `new(0x114)` 闭环)
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | pVtable | void* | unk_45BA88 |
  | 0x004 | m_strMountName | cHashedString | |
  | 0x00C | m_szMountPath | char[256] | |
  | 0x10C | bMounted | byte | |
  | 0x110 | m_strRoot | std::string(4B) | ctor `string("")`;MountWithMountPoint 中 assign("data/…")+append(path) |

- 证据:
  - ctor 0x271442 / 0x2713ec:`+272 string("")`(std::string::string 0x343566)
  - Mount 0x2715bc:无 "=" 时直接 Set+strncpy;有 "=" 时走 MountWithMountPoint;置 +0x10C=1
  - MountWithMountPoint 0x271514(ghidra):`string@0x110 assign("data")→append→append("/")`,+4 cHashedString,+0xC strncpy 0xFF,+0x10C=1
  - dtor 0x2714e2/0x2714e8;OpenRead 0x27253e / Load 0x271bee / Exists 0x2717cc / Write 0x2720ec 等虚方法
- 回写建议: 重建(0x114 = 276B;与 `new(0x114)` 互证)

---

## KleiFile::ZipFileSystem

- 状态: 待恢复
- 大小: 0x114 = 276B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | pVtable | void* | unk_45B9F8 |
  | 0x004 | m_strMountName | cHashedString | Mount 时 `Set(左值)` |
  | 0x00C | m_szMountPath | char[256] | strncpy 0xFF |
  | 0x10C | bMounted | byte | |
  | 0x110 | pZipArchive | void* | zip_open 返回值;ctor 置 0 |

- 证据:
  - ctor 0x26a9e6 / 0x26a9ac:`+1..+2=0,+0x10C=0,+0x110=0, vtable=unk_45B9F8`
  - Mount 0x26aad4:`*(cHashedString*)(this+4)=v12; strncpy(this+12,src,0xFF); *(byte*)(this+0x10C)=1; *(this+0x110)=zip_open(...)`
  - MountZip 0x26b102 / UnmountZip 0x26b178(ghidra):直接 Log "Unsupported" + Assert BREAKPT(zipfilesystem.h(35))——无额外 zip 挂载表字段
  - dtor 0x26aa58/0x26aa90/0x26aa20
- 回写建议: 重建(0x114 = 276B)

---

## KleiFile::MemoryCache

- 状态: 待恢复(注意:Ghidra 现有 `/MemoryCache` 24B 是 std::_Rb_tree 头(nM_cache_pad/color/parent/left/right/count),并非本类型,名字撞车)
- 大小: 0x14 = 20B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | nMaxSize | int32 | Init 时 = InitParams[0](0x1400000) |
  | 0x004 | nRemaining | int32 | Init 时 = nMaxSize;Cache 中随 Prune 增长 |
  | 0x008 | m_cache | std::vector<FileHandle*>(12B) | begin/end/cap |

- 证据:
  - `KleiFile::Init` 0x26c5cb:`new(0x14); v[0]=v[1]=max; v[2..4]=0`
  - `MemoryCache::Cache` 0x26ddc4(IDA):`+2`=begin,`+3`=end,`+1`=剩余,`+0`=上限;文件大小取 `FileHandle+0x11C`;`std::vector<FileHandle*>::insert((char*)this+8, …)`
  - `MemoryCache::Prune` 0x26e21c / `Add` 0x26e1d2 / dtor 0x26e430(ghidra:遍历 vector@+8..+0xC 后释放)
- 回写建议: 新建(20B,路径建议 `/Demangler/KleiFile/MemoryCache`,避免与现有 24B map 头 `/MemoryCache` 冲突)

---

## KleiFile::DLCMount

- 状态: 待恢复
- 大小: 0x10 = 16B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | nAppId | int32 | Steam DLC AppID |
  | 0x004 | m_strName | std::string(4B) | "DLC%04d" 格式化名 |
  | 0x008 | nField_0x08 | int32 | 0 |
  | 0x00C | bEnabled | byte | dlcinfo.txt 中非 "DONT_MOUNT" 为 true |

- 证据:
  - `cApplication::GetDLCInfo` 0x734e(IDA):读 dlcinfo.txt → `map<int,DLCMount>::operator[]` 结果 `v23`:`*v23=nAppId; string@v23+1; v23[2]=0; *(byte*)(v23+12)=bEnabled`;再 `list<DLCMount>::_M_create_node` 拷入 list
  - `KleiFile::RegisterMount` 0x26c9a4:`list<DLCMount>::_M_create_node(sMountedDLC, DLCMount&)` → 16B 值拷贝
  - map/list 模板(`_Rb_tree<int,pair<int,DLCMount>>` 0xa854 等)均 1B 占位,随 DLCMount 定型后可顺带
- 回写建议: 新建(16B;连带 std::list/map 模板类型受益)

---

## FileUtil / DirectoryUtils(静态工具类)

### FileUtil
- 状态: 跳过(纯静态函数集合,无实例/无数据成员)
- 大小: 不适用
- 字段: —
- 证据: 7 个静态函数:ExtractFilename 0x26b22b、ExtractPath 0x26b2a0、RemoveExtension 0x26b3af、ExtractExtension 0x26b4c6、HasExtension 0x26b5c4、ResolveRelativePath 0x26b66e、Exists 0x26b7e2;无 ctor/dtor/vtable
- 回写建议: 跳过(保留 1B 占位或删占位)

### DirectoryUtils
- 状态: 跳过(静态函数集合);嵌套类型 tFileDetails 待恢复
- 大小: 不适用(静态);tFileDetails = 0x0C = 12B
- 证据: DirectoryExists 0x25a12b、CreateDir 0x25a155、DelFile 0x25a186、DetailedDirectoryListing 0x25a26b、DirectoryListing 0x25a4dd、RecursivelyDeleteDirectory 0x25b596、RecursivelyCopyDirectory 0x25b5d2、EnsurePathExists 0x25bfa5 等,均静态
- 回写建议: DirectoryUtils 跳过;tFileDetails 新建(12B,见下)

### DirectoryUtils::tFileDetails
- 状态: 待恢复
- 大小: 0x0C = 12B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | m_strName | std::string(4B) | 文件名 |
  | 0x004 | m_time | int64(8B) | st_mtimespec.tv_sec(64 位 time_t)[INFERENCE:结合 stat 上下文与 8B 拷贝] |

- 证据:
  - `_Rb_tree<…tFileDetails…>::_M_create_node` 0x25c564(ghidra):`new(0x1C)`;string ctor @ node+0x10;`*(int64*)(node+0x14) = *(int64*)(value+4)` → 值域 = 0x1C-0x10 = 12B
  - `_M_destroy_node` 0x199524(ghidra):仅销毁 node+0x10 一个 string → tFileDetails 只含 1 个 string
  - `DetailedDirectoryListing` 0x25a26b(IDA):stat 后 `_M_insert_equal` 入 multiset
- 回写建议: 新建(12B,路径 `/Demangler/DirectoryUtils/tFileDetails`)

---

## cReader(精化验证)

- 状态: 已存在/验证通过
- 大小: 0x14 = 20B(与 types_common.h 一致)
- 字段:

  | 偏移 | 名称 | 类型 |
  |---|---|---|
  | 0x000 | pVtable | void*(unk_462584) |
  | 0x004 | nReadHead | int32 |
  | 0x008 | dwBufferLength | uint32 |
  | 0x00C | pBuffer | void* |
  | 0x010 | bOwnsBuffer | byte |
  | 0x011 | _pad | byte[3] |

- 证据: ctor 内联(读路径 new + Read 系列);dtor 0x1357b0 / 0x1c8310:`vtable@0` + `if (bOwnsBuffer@0x10 && pBuffer@0xC) delete`;Read 模板 0x1357f4/0x135876/0x1c8638/0x284130、ReadString 0x285c16、SkipBytes 0x285c6c(仅 `nReadHead += n`)
- 回写建议: 保留(无需改动)

## cWriter(精化验证)

- 状态: 已存在/验证通过
- 大小: 0x10 = 16B(与 types_common.h 一致)
- 字段:

  | 偏移 | 名称 | 类型 |
  |---|---|---|
  | 0x000 | pVtable | void* |
  | 0x004 | m_buffer_begin | void* |
  | 0x008 | m_buffer_end | void* |
  | 0x00C | m_buffer_cap | void* |

- 证据: `cHashedString::Write` 0x283fae(ghidra):`std::vector<char>::push_back((char*)(cWriter+4))` ×4 → 内嵌 vector<char> 起于 +4;TagSet::Write 0x282a76 同构
- 回写建议: 保留(无需改动;字段可改名为 m_vecBuffer[3] 便于阅读,可选)

---

## BinaryBufferReader

- 状态: 待恢复
- 大小: 0x10 = 16B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | pVtable | void* | unk_45BBB8(虚:ReadU8..ReadU64/String 等,ReadU32 在 vtable+36) |
  | 0x004 | nOffset | int32 | 读游标;`operator>>(string)` 与 `rsERi` 均 `pBuffer+nOffset` 后自增 |
  | 0x008 | pBuffer | void* | ctor 取 `Buffer::vtable[+12]`(GetData) |
  | 0x00C | dwBufferLength | uint32 | ctor 取 `Buffer::vtable[+8]`(GetSize) |

- 证据:
  - ctor 0x27f006/0x27f07e(IDA):`+0=vtable; +4=0; +8=buf->vtable[3](); +12=buf->vtable[2]()`
  - `operator>>(std::string&)` 0x27f20e:虚调用 vtable+36 读长度 → `string(ptr=+1+ +2, len)` → `+1 += len`
  - `ReadBytes` 0x27f3ae / `SkipBytes` 0x27f3de
- 回写建议: 新建(16B;EndianSwapped 变体继承同布局,见下)

## BinaryBufferWriter

- 状态: 待恢复
- 大小: 0x0C = 12B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | pVtable | void* | unk_45BC08 |
  | 0x004 | pBuffer | Buffer* | 非拥有;ctor 存 Buffer& |
  | 0x008 | nOffset | uint32 | 写游标;WriteBytes 后自增 |

- 证据:
  - ctor 0x27f3ea/0x27f40c(IDA):`+0=vtable; +1=Buffer*; +2=0`
  - `WriteBytes` 0x27f794:`memcpy(nOffset + Buffer::vtable[+12](buf), src, n); nOffset += n`
  - 运算符族 0x27f438..0x27f672
- 回写建议: 新建(12B)

## GrowableBinaryBufferWriter

- 状态: 待恢复
- 大小: 0x08 = 8B
- 字段:

  | 偏移 | 名称 | 类型 | 说明 |
  |---|---|---|---|
  | 0x000 | pVtable | void* | unk_45BC68(虚 WriteBytes @ vtable+8) |
  | 0x004 | pVec | std::vector<char>* | 外部 vector 引用,非拥有 |

- 证据:
  - ctor 0x27f7d2/0x27f7ec(IDA):`+0=vtable; +1=vector<char>*`
  - `WriteBytes` 0x27fa84:`size=end-begin; vector::resize(size+n,0); memcpy(begin+size, src, n)`(虚拟,EndianSwapped 派生覆盖)
- 回写建议: 新建(8B)

## EndianSwappedBinaryBufferReader

- 状态: 待恢复(继承 BinaryBufferReader,同布局)
- 大小: 0x10 = 16B
- 字段: 同 BinaryBufferReader,仅 vtable = unk_45BD08(先置基类 45BBB8 再覆盖)
- 证据:
  - ctor 0x27fdf4/0x27fe84(IDA):先执行 BinaryBufferReader ctor 体(vtable=45BBB8,填 +4/+8/+12),再 `vtable=45BD08`
  - `operator>>(uint&)` 0x28004e:`v=*(uint*)(+8 + +4); +4+=4; v=_byteswap_ulong(v)`(各基本类型 operator 内联 swap;string 走虚 ReadU32 覆盖)
- 回写建议: 新建(16B,建议作为 BinaryBufferReader 派生类型)

## GrowableEndianSwappedBinaryBufferWriter

- 状态: 待恢复(继承 GrowableBinaryBufferWriter,同布局)
- 大小: 0x08 = 8B
- 字段: 同 GrowableBinaryBufferWriter,仅 vtable = unk_45BCB8
- 证据:
  - ctor 0x27fad4/0x27faee(IDA):`+0=vtable(45BCB8); +1=vector<char>*`
  - `operator<<(uint)` 0x27fc8c:`v=_byteswap_ulong(x); (vtable+8)(this,4,&v)` → 虚调 WriteBytes
- 回写建议: 新建(8B,建议作为 GrowableBinaryBufferWriter 派生类型)

---

## 回写建议汇总

| 类型 | 建议 | 大小 | 关键证据 |
|---|---|---|---|
| KleiFile | 跳过(静态模块) | — | Init 0x26c5cb / Startup 0x99ea 调用链 |
| KleiFile::InitParams | 新建 | 8B | Startup:`{0x1400000, 0x80}` |
| KleiFile::FileHandle | 重建 | 344B (0x158) | Pool::sChunk `count*0x158`;dtor Semaphore@0x154 |
| KleiFile::FileSystem | 新建(抽象基类) | 272B (0x110) | Zip/Local ctor 公共前缀 + Mount 字段写入 |
| KleiFile::LocalFileSystem | 重建 | 276B (0x114) | ctor 0x271442 + `new(0x114)` @ 0x99ea |
| KleiFile::ZipFileSystem | 重建 | 276B (0x114) | ctor 0x26a9e6 + Mount 0x26aad4 |
| KleiFile::MemoryCache | 新建(勿覆盖 `/MemoryCache` 24B map 头) | 20B (0x14) | Init new(0x14) + Cache/Prune vector@+8 |
| KleiFile::DLCMount | 新建 | 16B (0x10) | GetDLCInfo 0x734e 字段写入 |
| FileUtil | 跳过(静态) | — | 7 静态函数,无 ctor |
| DirectoryUtils | 跳过(静态) | — | 静态函数集 |
| DirectoryUtils::tFileDetails | 新建 | 12B (0x0C) | _M_create_node 0x25c564 |
| cReader | 保留(验证通过) | 20B | dtor 0x1357b0 字段闭环 |
| cWriter | 保留(验证通过) | 16B | cHashedString::Write 0x283fae |
| BinaryBufferReader | 新建 | 16B | ctor 0x27f006 + rsERSs 0x27f20e |
| BinaryBufferWriter | 新建 | 12B | ctor 0x27f3ea + WriteBytes 0x27f794 |
| GrowableBinaryBufferWriter | 新建 | 8B | ctor 0x27f7d2 + WriteBytes 0x27fa84 |
| EndianSwappedBinaryBufferReader | 新建(派生) | 16B | ctor 0x27fdf4 + rsERi 0x28004e |
| GrowableEndianSwappedBinaryBufferWriter | 新建(派生) | 8B | ctor 0x27fad4 + lsEj 0x27fc8c |

## 备注/风险

1. **MemoryCache 命名冲突**:Ghidra 现有 24B `/MemoryCache`(字段 pad/color/parent/left/right/count)实为 std::map 头,与 KleiFile::MemoryCache(20B,vector 式)无关;回写时必须区分路径,勿用同名覆盖。
2. **FileHandle 语义字段**(mOp/mMode/mStatus):+0 在 ctor=5、Initialize=Op 参数;+0x114 在 Initialize=Mode 参数;+4 由 GetStatus 返回(1/2 进行中、3 完成、4 Freed、5 Deleted)。枚举值未逐一取证,字段名按用途标注。
3. **tFileDetails +4..+0xB**:8B 拷贝与 stat mtime(64 位)上下文吻合,标记 [INFERENCE];如后续找到 operator< 实现可再确认。
4. **Buffer 类**(BinaryBufferReader/Writer 依赖,接口 `vtable[+8]=GetSize, vtable[+12]=GetData`)本身仍为 1B 占位,不在本分片目标,建议后续单独恢复。
5. **cReader/cWriter 已存在且与 types_common.h 一致**,本分片仅验证未改动。
