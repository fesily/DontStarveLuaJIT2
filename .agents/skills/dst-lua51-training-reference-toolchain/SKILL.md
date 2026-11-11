---
name: dst-lua51-training-reference-toolchain
description: "DST LuaJIT injector aborts with \"unresolved Lua functions\" (lua_setfuncchunkname/lua_tolstring): diagnose a wrong-toolchain Mod/deps/lua51.dll training PE and verify via pre-push."
---

# Strategy

The injector resolves the game binary's Lua exports by fingerprinting the export bodies of the *training PE* `Mod/deps/lua51.dll` against the game module
(`src/DontStarveInjector/plugins/plugin_core_vm/signature_load/DontStarveSignature.cpp`). Therefore that DLL is a **build input**, not a shipped artifact to regenerate casually.
A modern-toolset rebuild keeps every export but changes every body, so runtime matching drops entries and the game dies at startup.

# Diagnosis

1. Symptom: dialog / log line `fatal: unresolved Lua functions: <names>`; logs live next to the binaries:
   - `"C:/Program Files (x86)/Steam/steamapps/common/Don't Starve Together/bin64/DontStarveInjector_{client,server}.log`
   - `FunctionRelocation.log` in the same dir.
2. Confirm which PE is deployed:
   - `ls -l` size — the good committed build is 179712 bytes.
   - CRT import: `strings -n 6 <dll> | grep -i '^MSVCR'` must print `MSVCR90.dll` (VC9/VS2008, same generation as the game's Lua 5.1). `VCRUNTIME140` means a VS2015+ rebuild and is wrong.
   - Compare with git: `git cat-file blob HEAD:Mod/deps/lua51.dll > /tmp/c.dll` and compare size/imports; `git status --porcelain Mod` flags a poisoned deploy.
3. Check the copies: repo `Mod/deps`, deployed workshop item (`steamapps/workshop/content/322330/3444078585/deps/lua51.dll` + `.pkg` twin, they are the same bytes), and the staged build trees `builds/<preset>/src/DontStarveInjector/<Config>/deps/lua51.dll`.

# Repair

```
git checkout -- Mod/deps/lua51.dll
rm -rf src/lua51/release src/lua51/obj src/lua51/*.obj
cmake --install builds/ninja-multi-vcpkg --config RelWithDebInfo   # restages + deploys
strings -n 6 Mod/deps/lua51.dll | grep -i '^MSVCR'                 # expect MSVCR90.dll
```

# Prevention

`src/lua51/build_lua51.bat` requires the VC9 toolchain `H:\vc2008-cli`; without it the script exits 1 with an explanation. Forcing the installed modern VS needs `set LUA51_ALLOW_MODERN_TOOLSET=1`, and that artifact must never be installed/deployed (the CMake install rule prefers `src/lua51/release/lua51.dll` over the committed one — deleting the folder is what restores the fallback to `Mod/deps`).

# Verification (never trust "build succeeded")

Run the real gate: `sh .githooks/pre-push origin <url> < /dev/null`.
- Green = 95/95 ctest plus install/deploy. Inspect `builds/ninja-multi-vcpkg/Testing/Temporary/LastTest.log` (header start time, `grep -c "Test Failed"` = 0) because the hook output is long.
- The tests that actually exercise signature resolution and a real launch: `plugin_client_inject_smoke`, `plugin_client_host_smoke`, `plugin_dedicated_sim_pause`, `game_mod_throw_abort`, `windows_signatures`, `windows_signatures_cache`.
- Delete any scratch build tree you created (`builds/_cfgcheck`): `tools/pre_push.py` auto-picks the *newest configured* build dir and will fail with "no built tests found".
- A fresh configure needs `-DCMAKE_MAKE_PROGRAM=<VS bundled ninja.exe>` when neither `cmake` nor `ninja` is on PATH; reuse `-DVCPKG_INSTALLED_DIR=<existing build tree>/vcpkg_installed -DVCPKG_MANIFEST_INSTALL=OFF` to avoid reinstalling ports.
