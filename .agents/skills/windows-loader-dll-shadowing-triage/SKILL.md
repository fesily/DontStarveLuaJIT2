---
name: windows-loader-dll-shadowing-triage
description: "Windows loader failures (0xc0000135/0xc0000139) from PATH DLL shadowing: reproduce, resolve imports, app-local copy fix"
---

# Triage 0xc0000135 / 0xc0000139 in Windows test binaries

Use when a Windows exe/test fails with "DLL not found" (0xc0000135) or "procedure entry point not found" (0xc0000139), especially under ctest, and the missing symbol/DLL name looks unrelated (e.g. `jvm.dll`, `zip_file_add`).

## 1. Get the facts without dialogs

Run the exe with loader hard-error dialogs suppressed and read the exit code:

```python
import ctypes, subprocess, os
k = ctypes.windll.kernel32
old = k.SetErrorMode(0x0001)  # SEM_FAILCRITICALERRORS
p = subprocess.run([exe], cwd=os.path.dirname(exe), capture_output=True, text=True)
print(hex(p.returncode & 0xffffffff))
k.SetErrorMode(old)
```

0xC0000135 = a statically imported DLL is missing.
0xC0000139 = every DLL loaded, but an imported symbol is absent (wrong same-name DLL).

## 2. Map imports to the DLL actually loaded

```python
import pefile
pe = pefile.PE(exe)
print([d.dll.decode() for d in pe.DIRECTORY_ENTRY_IMPORT])
# do NOT keep pefile.PE objects alive: their mmap locks the file (LNK1168)
```

Then resolve each imported name the way the loader does: exe directory first, then every PATH entry. Common hijacks: JDK `bin/zip.dll`, `bin/java.dll`, game/engine DLLs, vendored runtime DLLs.

Check the resolved file's imports and exports:

```python
pe = pefile.PE(resolved)
print([d.dll.decode() for d in pe.DIRECTORY_ENTRY_IMPORT])
print([e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name])
```

Example: a libzip consumer importing `zip.dll` resolves to JDK `bin/zip.dll`; that DLL imports `jvm.dll` (missing -> 0xc0000135) and exports no `zip_file_add` (-> 0xc0000139).

## 3. Fix: remove PATH dependence

Deploy the correct runtime app-local with a POST_BUILD copy (preferred):

```cmake
add_custom_command(TARGET mytest POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:libzip::zip>" "$<TARGET_FILE_DIR:mytest>")
```

Also copy transitive runtime DLLs the imported DLL itself needs (e.g. `bz2d/zlibd1` for Debug, `bz2/zlib1` for Release). For a one-off diagnosis, temporarily prepend the correct directory to PATH.

## 4. Verify through the real entry point

Run the test both directly and through ctest/the repo gate (`python tools/pre_push.py -R <regex>`, then the full gate). Never trust a direct run alone.

## Pitfall

If binaries were partially rebuilt, a version symbol (e.g. `luaJIT_version_2_1_<relver>`) can mismatch between exe and DLL: rebuild the full configuration before blaming the loader.
