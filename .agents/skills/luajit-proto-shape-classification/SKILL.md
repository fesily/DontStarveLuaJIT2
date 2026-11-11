---
name: luajit-proto-shape-classification
description: "Measure Lua proto shape (sizebc/numline/density) with jit.util to classify DST mod files as normal vs VM-obfuscated shell, without executing them."
---

# 测量 DST mod 的 Lua proto 形状（判断是否 VM/生成壳）

目标：在**不执行**文件的前提下，用 proto 结构指标区分“正常脚本”和“VM 虚拟化壳/生成代码”。

## 前提

- 用仓库自建 VM：`builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe`
- 必须设置 `LUA_PATH` 含 `luajit/src/?.lua` 与 `Mod/scripts/?.lua`（fork 把 `jit/vmdef.lua` 移到了 `Mod/scripts/jit/`，否则 `jit.util`/`-jdump` 加载失败）

```
LUA_PATH="<repo>/luajit/src/?.lua;<repo>/Mod/scripts/?.lua;;" <repo>/builds/ninja-multi-vcpkg/luajit/RelWithDebInfo/luajit.exe walk.lua <files...>
```

## 遍历 proto 树

`jit.util.funck(fn, -i)` 返回 GC 常量；子函数返回的是 **`type == "proto"`**（不是 `"function"`），必须两类都递归。`jit.util.funcinfo(x)` 接受 function 或 proto。

```lua
local ju = require("jit.util")
local function walk(x, seen, m)
  local k = tostring(x); if seen[k] then return end; seen[k] = true
  local info = ju.funcinfo(x)                 -- bytecodes, nconsts, gcconsts, linedefined, lastlinedefined, stackslots
  local lines = info.lastlinedefined - info.linedefined
  m.maxbc = math.max(m.maxbc, info.bytecodes)
  m.density = math.max(m.density, info.bytecodes / (lines + 1))
  for i = 1, info.gcconsts do
    local v = ju.funck(x, -i)
    if type(v) == "proto" or type(v) == "function" then walk(v, seen, m) end
  end
end
```

## 判定

- VM/生成壳：`sizebc >= 200 and sizebc/(numline+1) >= 128`
- 实测：正常 mod 文件密度上限 48，明文 VM 壳 31107（650×）
- 反例：Hercules `--virtual_machine` 输出密度仅 5.2 → 需补大字符串常量/水印/壳 preamble 信号
- 未命中默认 JIT 开（正常脚本必须保持可 JIT）

## 批量扫描

Windows 下用 `io.popen('dir /b /s "<mods>\*.lua"')` 枚举；`loadfile` 失败即密文文件（例如 `workshop-2847908822/1.lua..23.lua` 全部 parse fail）。

## 采集解密后的真实文本

`luajit/src/lj_load.c` 的 `LJ_DS_LOADLOG` 会包装 reader 并把实际喂给 parser 的文本 dump 到 `ds_loaddump/`：编译加 `-DLJ_DS_LOADLOG=1`，运行时 `DS_LOADLOG=1`（可加 `DS_LOADLOG_FILTER=<substr>`）。用它验证阈值/签名，不要靠猜。

## 注意

- `lua_loadx` 是所有加载路径的唯一漏斗（loadfile/loadbuffer/load(reader)），但分不出 Lua 内建与引擎 C 调用；需要来源区分时在 `lib_base.c` 的 `load_aux` 做。
- 标记 NOJIT：`setptmode`/`setptmode_all` 是 static，需自己写递归打 `PROTO_NOJIT`；解析刚结束无 trace，不需要 flush。
