---
name: vs2008-express-portable-extract
description: "Extract a usable VS2005/2008 Express C++ toolchain (cl/link/rc + CRT headers + Windows SDK) from installed-media ISO/DVD without running setup; covers Ixpvc.exe SFX, msiexec /a, mspdb80 PATH/C1902, SxS debug CRT."
---

# 从 VS2005/2008 Express 安装介质零安装解包 C++ 工具链

目标：只有安装盘/ISO/光盘，不想安装，只要 cl.exe + 头文件 + lib + Windows SDK。

## 1. 认清介质结构

VS2008 Express 一体化 DVD 根目录：

```
D:\VCExpress\Ixpvc.exe     ← VC++ 产品 SFX CAB (58MB)
D:\VCExpress\WCU\WinSDK\   ← Windows SDK 负载
D:\VCExpress\WCU\vcredist_x86.exe
D:\VBExpress / VCSExpress / VWDExpress   ← 其它产品，忽略
```

`Ixpvc.exe` 是 PE + `.rsrc_1` 里的 CAB，内含 `vs_setup.msi`（产品 MSI，3.9MB）+ `vs_setup.cab`（payload，56MB → 展开约 332MB，文件名被改成 `FL_cl_exe_7279_x86_ln.<guid>` 这类 mangled 名）。payload 里**没有** windows.h —— Windows SDK 是独立 WCU 组件。

## 2. 解包（7z + msiexec 管理安装）

```
7z x D:\VCExpress\Ixpvc.exe -o%T%\vsx
copy %T%\vsx\WCU\vcredist_x86.exe %T%\vsx\            # 关键，见 §4
msiexec /a %T%\vsx\vs_setup.msi /qn TARGETDIR=C:\VSE /L*v %T%\log.txt
```

`/a` = 管理安装：只按 MSI 的 Directory/File 表展开出真实目录树（`Program Files\Microsoft Visual Studio 9.0\Vc7\{bin,include,lib}`、`Common7\IDE`、`Windows\winsxs\...`），**不注册组件、不写卸载项**，等价于"解压"。

Windows SDK 同样处理：

```
7z x D:\VCExpress\WCU\WinSDK\WinSDK_Build.exe        -o%T%\sdk1   # VistaClientHeadersLibs-x86.msi → Include/ Lib/
7z x D:\VCExpress\WCU\WinSDK\WinSDK_Exp32Tools.exe   -o%T%\sdk2   # VistaClientExpressTools-x86.msi → Bin/ (rc.exe midl.exe mt.exe)
msiexec /a %T%\sdk1\VistaClientHeadersLibs-x86.msi /qn TARGETDIR=C:\VSE\SDK\Headers
msiexec /a %T%\sdk2\VistaClientExpressTools-x86.msi /qn TARGETDIR=C:\VSE\SDK\Tools
```

先用 `7z l -slt` 列一遍条目，确认 cl.exe/c1xx.dll/c2.dll/link.exe/stdio.h 都在，再动手。

## 3. 环境（必须含 IDE 目录）

```
set PATH=C:\VS2008\VC\bin;C:\VS2008\IDE;C:\VS2008\SDK\Bin;%PATH%
set INCLUDE=C:\VS2008\VC\include;C:\VS2008\SDK\Include
set LIB=C:\VS2008\VC\lib;C:\VS2008\SDK\Lib
```

- `IDE` 目录只需保留 `mspdb80.dll mspdbcore.dll msobj80.dll mspdbsrv.exe symsrv.dll dbghelp.dll`；其余（VCExpress.exe、模板、vcpackages）可全删。
- cl.exe **静态导入** `mspdb80.dll`，缺了就是启动即 `0xC0000135`（DLL not found），不是 SxS 错。
- **不要**把 mspdb*.dll 拷进 VC\bin —— 会得到 `fatal error C1902: Program database manager mismatch`。放在 IDE 目录并加进 PATH 才正常。

## 4. 坑

| 现象 | 原因 / 修法 |
|---|---|
| `/a` 返回 1603，日志里 `Error 1308.Source file not found: ...\vcredist_x86.exe` | MSI 期望 vcredist 在 MSI 同目录；先 copy 过去再跑，否则整包回滚 |
| `cl` 启动返回 0xC0000135 | PATH 缺 `Common7\IDE`（mspdb80.dll） |
| `C1902 Program database manager mismatch` | mspdb dll 被复制到 VC\bin 或版本混用；只留 IDE 一份 |
| `rc /nologo` → `RC1106: invalid option: -ologo` | SDK 6.0A 的 rc.exe 不支持 /nologo，直接 `rc /fo x.res x.rc` |
| `/MDd` 生成的 exe 启动报 SxS incorrect | 系统无 DebugCRT；`VC\redist\Debug_NonRedist\x86\Microsoft.VC90.DebugCRT` 放 exe 同目录或同名子目录都不成立 → 开发用 `/Zi /MD` |
| 分发 `/MD` 产物 | 目标机装 `WCU\vcredist_x86.exe`，或改 `/MT` |
| 删除/移动目录报 WinError 5 | `mspdbsrv.exe` 与 Windows Installer 服务持有句柄：`taskkill /F /IM mspdbsrv.exe`；仍锁的文件 DELETE 被拒但 rename 允许 → 改名 `.del` 再删（或重启后删 Temp 里的 msi/cab） |

## 5. 验证（每次都要真跑）

```
call vcvars.bat && cl /nologo /Zi /EHsc /MD a.cpp && a.exe
rc /fo a.res a.rc && link /nologo a.obj a.res /out:a2.exe
cl /nologo /MT b.c && b.exe          # 验证不依赖系统 CRT
```

注意 VC9 是 C++03：`std::vector<int> v{1,2,3}` 会报 C2601，用 `v(3,7)` 形式测。

## 6. 能力边界

VC++ 2008 **Express** 只带 x86 `cl.exe`，没有 x64 编译器（SDK 的 x64 库存在但无 amd64 cl）。要 x64 需标准/专业版或 VS2010+。

成品参考布局（218MB）：

```
C:\VS2008\
  VC\   bin include lib redist vcvarsall.bat
  IDE\  mspdb80 mspdbcore msobj80 mspdbsrv symsrv dbghelp
  SDK\  Include Lib Bin
  vcvars.bat
```
