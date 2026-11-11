---
name: dst-clipboard-paste-hook-locate
description: Locate DST paste/clipboard hook targets (IsPasteKey / OnInputEvent / WindowManager::GetClipboardString / Lua GetClipboardData stub) in Windows/macOS/Android binaries by string xrefs + call-graph walk; use for image-paste support or clipboard interception.
---

# DST 剪贴板/粘贴 hook 点定位（Windows / macOS / Android）

用途：为 DST 各平台二进制定位“粘贴/复制”拦截点，或实现“粘贴图片”支持。铁律：先按语义核对，再按字符串/调用图重定位，绝不写死 RVA（签名匹配）。

## 语义（先核对目标二进制）
- 触发：`DontStarveInputHandler::IsPasteKey(key)`：非 mac = KEY_V(0x76) + GetKeyState(KEY_CTRL=0x191)；mac = KEY_V + KEY_LSUPER(0x137)/KEY_RSUPER(0x138)；Linux 追加 KEY_INSERT(0x115)+KEY_SHIFT(0x192)。Lua 镜像：`scripts/input.lua:505 Input:IsPasteKey`；消费点 `textedit.lua:280`、`textedit_steamdeck.lua:286`、`texteditlinked.lua:51`、`consolescreen.lua:90`、`redeemdialog.lua:274`。
- 消费：OnInputEvent KEYDOWN(type=4) → 读剪贴板 → `utf8_scan_len`/`utf8_sub_str` 逐 UTF-8 字符派发 `cInputTextEvent` → `TheFrontEnd:OnTextInput` → 焦点 widget（`TextEdit:OnTextInput` 做字符过滤：limit、validchars/invalidchars、默认黑名单 \b(8)/\x16(22)/\x1b(27)，禁换行再+10/13）。
- `TheSim:GetClipboardData()` 在现行桌面/Android 构建均为死 stub（push 常量空串）；Lua 侧粘贴分支实际不生效，唯一生效的是 C++ 路径。mac 旧 32 位构建连 C++ 粘贴分支都没有。

## 定位步骤（新版本重定位用）
1. Lua 绑定：`search_strings "GetClipboardData"` → 找到 luaL_Reg 表（xref，`{name,func}` 16 字节对，取 func 指针）。Windows 参考：串 0x140527788，表 0x14061cb38，func FUN_14004a440（push 常量空串 = stub）。Android：SimLuaProxy::GetClipboardData 0x8adbb8（同为 push 空串），mac：SimLuaProxy::GetClipboardData 0xf4818（调用真 getter）。
2. IsPasteKey：`search_strings "OSX_STEAM"` / `"LINUX_STEAM"` → xref 到的比较 0x76/0x115 常量 + vtable 槽 GetKeyState 的函数。参考：Windows 0x140050390（vtable 0x1406b5a00）；Android 0x784f1c。
3. 其唯一 caller = OnInputEvent（Windows 0x140055bc0；Android 0x784590；mac 0x1d6dc 无粘贴分支）。KEYDOWN 分支里调用形如 `GetClipboardString(std::string* sret)` 的函数 = 剪贴板读取点：
   - Windows x64：FUN_1403d6bc0（调用点 0x140055ec2）：直接 Win32 `OpenClipboard`/`GetClipboardData(0xD=CF_UNICODETEXT)`/`GlobalLock`→wstring→剔除 U+200B→UTF-8 上限 0x200(512B)；另被 3 个 vtable 引用。
   - Android AArch64：`WindowManager::GetClipboardString` 0x9d88d4，经 PLT 进外部 libSDL2.so → Java `org.libsdl.app.SDLClipboardHandler`（classes3.dex）：`clipboardHasText()=hasPrimaryClip()`，`clipboardGetText()=getPrimaryClip()→getItemAt()→ClipData.Item.getText()`（无 coerceToText）⇒ 图片 clip 的 getText()=null ⇒ 空串。
   - macOS 32 位旧构建：0x1d205e = `std::string("")` stub（唯一调用者 0xf4818）；二进制无 IsPasteKey、无 pasteboard 代码。触发只能来自 Lua（Cmd+V via scripts/input.lua）。
4. 校验锚点：粘贴逻辑内有 utf8_scan_len/utf8_sub_str（Windows FUN_140428810/FUN_140428b30；Android Util::utf8_scan_len/utf8_sub_str）与 cInputTextEvent vtable 派发（`DispatchEvent`）。

## 图片粘贴实现要点
- 引擎所有剪贴板 API 只认文本（std::string/lua string）：Windows 只读 CF_UNICODETEXT（图片仅 CF_DIB⇒NULL）；Android `Item.getText()` 对图片返回 null；mac SDL/引擎无类型判定。
- 支持图片：hook 上述读取点，在 hook 内自读 OS 剪贴板——Windows `IsClipboardFormatAvailable(CF_DIB/CF_DIBV5/RegisterClipboardFormatW("PNG"))`；mac `NSPasteboard generalPasteboard`（NSPasteboardTypePNG/TIFF/fileURL）；Android 同理需 Java 侧 coerce/自读。把替代文本（保存路径/占位符）写进其 sret，或自行插入并跳过原函数。
- 注意 Windows 原实现的 512B 截断与 U+200B 剔除；自行接管返回值可绕过。

## 验证
- Windows：复制一张图片 → 游戏内 Ctrl+V → 现状无任何字符（CF_UNICODETEXT 缺失）；hook 后应插入你返回的字符串。
- 定位是否找对：在剪贴板读取函数下断点/日志，按 Ctrl+V 应在该函数收到调用；文本剪贴板应产生逐字符 cInputTextEvent。
