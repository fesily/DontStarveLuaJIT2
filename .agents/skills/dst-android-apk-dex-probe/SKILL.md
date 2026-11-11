---
name: dst-android-apk-dex-probe
description: 无 jadx 逆向 DST Android APK：拆分包嵌套 zip、dex 类方法调用扫描（自写 mini dex parser）、JNI 字符串定位、与 dst-scripts/Ghidra MCP 交叉验证
---

# DST Android APK / dex probe（无 jadx）

适用：问题落在 Java/dex 或 SDL 层（剪贴板、IME、权限、JNI），或 libDontStarve.so 里找不到答案时。

## 1. 打开 APK
- `C:\Users\fesil\Downloads\DontStarveTogether_<ver>.apk.7z` **实际是 ZIP**（magic `PK\x03\x04`），内含 5 个 split APK：`base.apk`、`split_assets_dsandroid.apk`(约2GB assets)、`split_config.arm64_v8a.apk`(库)、`split_config.xxxhdpi/zh.apk`。
- `read` 工具因扩展名会按 7z 解析而失败；用 Python：
```python
import zipfile, io
outer = zipfile.ZipFile(r"C:/Users/fesil/Downloads/DontStarveTogether_1.1.28.apk.7z")
base = zipfile.ZipFile(io.BytesIO(outer.read("base.apk")))      # classes*.dex
cfg  = zipfile.ZipFile(io.BytesIO(outer.read("split_config.arm64_v8a.apk")))
```
- 成员是 deflate；≤50MB 的成员可直接全读进内存，**不要**读 2GB 的 assets 包。
- 库在 `lib/arm64-v8a/`：libDontStarve.so、**libSDL2.so**（外置！）、libEOSSDK.so、libpairipcore.so。

## 2. 字符串扫描
- dex：`data.count(b"needle")`，再提取含关键词的 ASCII 串：
```python
import re
for m in re.finditer(rb"[\x20-\x7e]{4,}", data):
    if b"lipboard" in m.group(): print(m.group())
```
- .so：找 JNI 桥名（`Java_org_libsdl_app_*`）和 GetMethodID 字面量（如 `clipboardGetText`/`clipboardHasText`）——它们揭示 native 调用的 Java 方法名。

## 3. 类方法 → 被调方法 映射（mini dex parser）
Header 偏移：string_ids 0x38/0x3C、type_ids 0x40/0x44、method_ids 0x58/0x5C、class_defs 0x60/0x64。
```python
def parse_dex(d):
    sid_sz, sid_off = struct.unpack_from("<II", d, 0x38)
    tid_sz, tid_off = struct.unpack_from("<II", d, 0x40)
    mid_sz, mid_off = struct.unpack_from("<II", d, 0x58)
    cd_sz,  cd_off  = struct.unpack_from("<II", d, 0x60)
    def uleb(off):
        r = s = 0
        while True:
            b = d[off]; off += 1; r |= (b & 0x7f) << s
            if not (b & 0x80): return r, off
            s += 7
    def sget(i):
        o = struct.unpack_from("<I", d, sid_off + 4*i)[0]
        _, st = uleb(o)
        e = st
        while d[e]: e += 1
        return d[st:e].decode("utf-8", "replace")
    def tget(i): return sget(struct.unpack_from("<I", d, tid_off + 4*i)[0])
    def mget(i):
        c, p, n = struct.unpack_from("<HHI", d, mid_off + 8*i)
        return tget(c), sget(n)
    return d, cd_off, cd_sz, mget, uleb

def scan_methods(d, cdata, mget, uleb):
    # class_data: 4xuleb sizes, fields(2xuleb), methods(uleb idx_diff, uleb access, uleb code_off)
    off = cdata
    sf, off = uleb(off); inf, off = uleb(off); dm, off = uleb(off); vm, off = uleb(off)
    for _ in range(sf+inf): _, off = uleb(off); _, off = uleb(off)
    def methods(cnt, off):
        idx = 0; res = []
        for _ in range(cnt):
            dI, off = uleb(off); acc, off = uleb(off); co, off = uleb(off)
            idx += dI; res.append((idx, co))
        return res, off
    dlist, off = methods(dm, off); vlist, off = methods(vm, off)
    for idx, co in dlist + vlist:
        if co == 0: continue
        regs, ins, outs, tries, dbg, n = struct.unpack_from("<HHHHII", d, co)
        io = co + 16   # insns
        calls = []
        for i in range(n):
            op = struct.unpack_from("<H", d, io + 2*i)[0] & 0xFF
            if 0x6e <= op <= 0x72 or 0x74 <= op <= 0x78:   # invoke-kind / -range
                mi = struct.unpack_from("<H", d, io + 2*(i+1))[0]
                c2, m2 = mget(mi)
                calls.append(c2.split("/")[-1] + "." + m2)
        cn, mn = mget(idx)
        yield cn, mn, calls
# 用法：遍历 class_defs(type_idx 名含关键词, 如 'SDLClipboardHandler') → scan_methods
```
- 实例结论（已证）：`SDLClipboardHandler.clipboardGetText()` = getPrimaryClip→getItemAt→`ClipData$Item.getText`（**非 coerceToText**）⇒ 图片 clip 无文本；`clipboardHasText()` = `hasPrimaryClip()`。

## 4. 交叉验证（仓库内）
- `<repo>/dst-scripts/` 是完整 DST Lua 树但**被 gitignore**：grep 需 `gitignore:false`；对整棵目录的 grep 不可靠 → 收敛到 `dst-scripts/scripts` 或单文件。
- Android C++ 侧：Ghidra program `libDontStarve.so`（符号表参考 `3rd/dst/game_decompiler/types_android.hpp`，含类方法名+地址）。
- 平台号：`AppVersion::GetPlatform()` @0xa659cc 直接 `return "Android"`。
- 文本输入的关键 Lua 消费点：`frontend.lua:221 TheInput:AddTextInputHandler`、`widgets/textedit.lua:206 OnTextInput`（字符过滤：limit/validchars/invalidchars/黑名单 \b \x16 \x1b）。
