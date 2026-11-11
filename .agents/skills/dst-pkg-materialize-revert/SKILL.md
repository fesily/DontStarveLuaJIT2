---
name: dst-pkg-materialize-revert
description: "A rebuilt DLL under Mod/ silently reverts to an older build: stale .pkg twins (PackagedModule::materialize) overwrite the canonical file at boot. Diagnose via sha1/ctime, delete .pkg, restore from git."
---

# Symptom

A DLL you just rebuilt under `Mod/` (most often `Mod/deps/lua51.dll`, `lua51DS*.dll`, `function_relocation.dll`) is back to an older build minutes later. `git status` shows it modified with an **old mtime**, tests behave like the old build, and nobody admits rebuilding it.

# Cause

`src/DontStarveInjector/core/PackagedModule.hpp`:

- `materialize()` / `materialize_directory()` copy `<name>.pkg` over the canonical `<name>` whenever the **bytes differ** — it does not compare mtimes, so a stale Workshop `.pkg` always wins over a newer rebuild.
- `std::filesystem::copy_file` keeps the source's last-write time, so the overwritten file looks old by mtime even though it was written now.
- The shell runs `materialize_directory(deps)` at boot, so any game launch with `DS_LUAJIT_INJECTOR=Mod/Injector.dll` (including the pre-push smoke tests) triggers it.

# Diagnose (fast)

```bash
sha1sum Mod/deps/lua51.dll Mod/deps/lua51.dll.pkg     # equal => pkg overwrote it
git show HEAD:Mod/deps/lua51.dll | sha1sum            # compare with the committed build
stat -c '%n mtime=%y ctime=%z' Mod/deps/lua51.dll     # mtime old, ctime recent
```

Also list `Mod/deps/*.dll` ctimes: several siblings rewritten in the same ~10 ms window is the signature of `materialize_directory`.

# Fix

```bash
rm -f Mod/Injector.dll.pkg Mod/deps/*.pkg Mod/plugins/*/*.pkg
git checkout HEAD -- Mod/deps/lua51.dll   # or rebuild
```

Regenerate `.pkg` only when publishing: `python tools/update_workshop_tags.py --push-content`.

# Prevention

- Never publish/stage `.pkg` from a source tree you keep building in; delete them before running the game or the pre-push gate.
- `.pkg` files are untracked; adding them to `.gitignore` keeps `git status` honest.
- If making `materialize()` timestamp-aware, keep the "atomic replace + same_image" concurrency guarantees intact.
