---
name: windows-cross-crt-stl-dll-mismatch
description: "Windows Debug exe crashes only in Debug because a shared dependency's std::string crosses the CRT ABI (wrong-config DLL on PATH); stage config-matched runtime DLLs"
---

# Symptom

A Windows tool/test exe works in Release/RelWithDebInfo but dies with `0xC0000005` (or reads garbage names / returns nonsense) in Debug, immediately, with no stack. Often inside third-party code that takes a `const std::string&` across a DLL boundary (here `peparse::IterSec`).

# Root cause class

An imported **shared** dependency whose public ABI carries `std::string` (or any STL container) is resolved at runtime by PATH, so a Debug consumer can load the **Release** build. MSVC `std::string` layout changes with `_ITERATOR_DEBUG_LEVEL` (`_Container_base12` vs `_Container_base0`), so the callee writes/reads the same object with a different field layout.

# Diagnosis (no debugger needed)

1. Check whether the dependency is shared at all: `find_package` config with `IMPORTED_LOCATION_<CFG>` pointing at a `.dll` (a 1 MB "static-looking" `.lib` can still be an import lib).
2. Build a 20-line probe against the dependency and run it under both DLLs:
   ```
   Debug exe + <pkg>/bin/pe-parse.dll        -> name='(null)'   (broken)
   Debug exe + <pkg>/debug/bin/pe-parse.dll  -> name='.text'    (correct)
   ```
   That isolates the mismatch from your own code.
3. Missing DLL shows as `0xC0000135`; the ABI mismatch shows as `0xC0000005` after at least one valid field (e.g. a buffer length) proves arguments are reaching the callback.

# Fix

Stage the config-matched runtime next to the consumer so PATH cannot pick the wrong copy:

```cmake
if (WIN32)
    add_custom_command(TARGET <tgt> POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_RUNTIME_DLLS:<tgt>>
            "$<TARGET_FILE_DIR:<tgt>>"
        COMMAND_EXPAND_LISTS
        VERBATIM)
endif()
```

Verify by deleting every `*.dll` next to the exe, rebuilding the target, and listing the directory: all shared imports (frida-gum, spdlog, fmt, pe-parse, zlib/bzip2) must reappear.

# Traps

- Do not "fix" this by prepending `Mod/deps` to PATH in a test — that is exactly the wrong copy.
- Running the exe from this repo's shell can report `command not found`; use `python -c "subprocess.run([exe], ...)"`.
- Rebuilding the target only re-runs POST_BUILD on relink; delete the exe to force it.
