---
name: luajit-gc-field-engine-marker
description: "Add an engine-only GCRef marker field to LuaJIT's GCproto (or any GC object): struct field, GC traversal, both proto-creation paths, LUA_API exports, MinGW build pitfalls, and a C harness that proves dump/load and forgery lose the marker."
---

# 给 LuaJIT 的 GC 对象加"引擎专用"字段并验证（DST fork）

场景：必须让 C++/引擎侧写入一个 Lua 层无法伪造的标记（本例：`GCproto.dschunkname`，
用于 traceback 守卫区分"真从磁盘加载的 chunk"和 `loadstring(code, "@fake")` 伪造的 source）。

## 1. 加字段（`luajit/src/lj_obj.h`）

放在被伪造字段旁边，注释写清"谁能写、为什么不进 dump"：

```c
GCRef chunkname;    /* 已有的、Lua 层可伪造的 debug source */
GCRef dschunkname;  /* 引擎专用标记：只有 loader 能写，dump 不序列化 */
```

## 2. 两条创建路径都要清零

- 源码解析：`lj_parse.c` 的 `fs_finish()`，紧跟 `setgcref(pt->chunkname, ...)`
- 字节码读取：`lj_bcread.c` 的 `lj_bcread_proto()`，同一个位置

```c
setgcrefnull(pt->dschunkname);
```

漏掉 `lj_bcread.c` ⇒ `load(string.dump(f))` 得到的 proto 里是垃圾指针。

## 3. GC 遍历（`lj_gc.c: gc_traverse_proto`）

```c
{ GCstr *s = strref(pt->dschunkname); if (s) gc_mark_str(g, s); }
```

`gc_mark_str` 是宏，**不判空**，必须自己判。

## 4. 导出 API（`lj_api.c`，`index2adr` 是 static，只有这个 TU 能用）

```c
static void ds_proto_setchunkname(lua_State *L, GCproto *pt, GCstr *s) {
  setgcref(pt->dschunkname, obj2gco(s));
  lj_gc_objbarrier(L, pt, s);
  if (pt->flags & PROTO_CHILD)
    for (ptrdiff_t i = -(ptrdiff_t)pt->sizekgc; i < 0; i++) {
      GCobj *o = proto_kgc(pt, i);                    /* 已是 GCobj* */
      if (o && o->gch.gct == ~LJ_TPROTO)              /* 不是 itype() */
        ds_proto_setchunkname(L, gco2pt(o), s);
    }
}
LUA_API void lua_ds_setchunkname(lua_State *L, int idx, const char *name) {
  TValue *o = index2adr(L, idx);
  if (!tvisfunc(o) || !isluafunc(funcV(o)) || !name) return;
  ds_proto_setchunkname(L, funcproto(funcV(o)), lj_str_newz(L, name));
}
LUA_API const char *lua_ds_getfuncchunkname(lua_State *L, int idx) {
  TValue *o = index2adr(L, idx); GCstr *s;
  if (!tvisfunc(o) || !isluafunc(funcV(o))) return NULL;
  s = strref(funcproto(funcV(o))->dschunkname);
  return s ? strdata(s) : NULL;
}
```

`LUA_API` 在 `LUA_BUILD_AS_DLL` 下自动 `dllexport`，不需要 .def；用
`objdump -p lua51.dll | grep lua_ds_` 确认导出。

## 5. Windows 构建（MinGW）

```bash
cd luajit/src && mingw32-make -j4        # 产出 lua51.dll + luajit.exe
```

已知坑：
- HEAD 的 MinGW 路径编译不过（`lib_io.c` 用 `lj_fseeko64`/`lj_ftello64`，`lj_io_patch.h` 没定义）：
  patch 分支加 `#elif defined(__MINGW32__)`（映射 `_fseeki64`/`_ftelli64`），宏分支加两条 `#define`。
- `lj_io_patch.h` 是**混合行尾**（patch 分支 LF、宏分支 CRLF）→ 只能按字节替换。
- 改了头文件但 `lj_load.o` 没重编时链接会报 `undefined reference to lj_fseeko64`：`touch lj_load.c` 再 make。

## 6. 验证 harness（放 `build/`，别提交）

```bash
gcc -O1 -I ../luajit/src probe.c -L../luajit/src -llua51 -o probe.exe
cp ../luajit/src/lua51.dll . && cmd.exe /c "probe.exe"
```

必测 7 项：
1. 未写标记 → `NULL`；写入后 → 期望串
2. 嵌套子 proto 继承标记
3. `string.dump` → `load` 后标记丢失（`source` 会带回来）
4. `loadstring(code,"@fake")` 伪造 source 但标记仍 `NULL`
5. C 闭包 / 非函数 → `NULL`；对非函数 set 不崩
6. 替换标记
7. 5 万条同长度字符串 + 两轮 full GC 后仍正确

## 7. 集成（插件侧）

PUC 侧两个函数用 gum 签名 hook 到新导出（`gum_module_find_export_by_name(LuaModule, ...)`），
writer 直接转发；reader **替换**掉原来基于 `lua_getinfo` 的版本，否则失去防伪造性质。

## 陷阱

- 探针**测不出**漏掉 GC mark：字符串被回收后内存未立即复用，内容照样对。mark 靠契约，不靠测试。
- 给 GC 对象加字段会改 `sizeof`，`sizept` 由 `sizeof` 推导会自动跟上，但必须重编所有变体 DLL。
- `lj_str_newz` 之后到 `setgcref` 之间**不能**再分配（GC 步进可能在分配点触发）；
  若将来插入分配,按 `lj_parse.c` 的写法 `setstrV(L, L->top, s); L->top++;` 先锚定。
- 用 Python 改 C 源码时必须二进制写入（默认会 LF→CRLF，5 行改动变成整文件 diff）。
