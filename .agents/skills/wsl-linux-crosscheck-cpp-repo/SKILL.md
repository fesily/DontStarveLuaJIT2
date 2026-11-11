---
name: wsl-linux-crosscheck-cpp-repo
description: "Cross-check Windows-first C++ changes on WSL Ubuntu: copy subset, build with vcpkg/CMake presets, run ctest, attribute failures against pristine sources, harness the untested paths"
---

# WSL Linux cross-check for a Windows-first C++ repo

Use when you changed Windows-validated C++ in a repo that also ships Linux builds and you have no Linux host (e.g. DontStarveLuaJIT2). Goal: prove the change compiles and behaves on Linux without pretending an end-to-end run happened.

## 1. Copy a buildable subset (not the whole tree)

Exclude generated/vendor trees; they are large and platform-specific.

```bash
rsync -a --info=progress2 \
  --exclude ".git" --exclude "builds" --exclude "vcpkg_installed" --exclude ".venv" \
  --exclude ".steam" --exclude "__pycache__" --exclude ".pytest_cache" \
  --exclude "tools/angle" --exclude "tools/frida" --exclude "3rd/angle" \
  --exclude "3rd/frida-gum-build" \
  --exclude "vcpkg/buildtrees" --exclude "vcpkg/packages" --exclude "vcpkg/installed" \
  --exclude "vcpkg/.git" --exclude "vcpkg/vcpkg.exe" \
  /mnt/c/Users/<user>/<Repo>/ ~/<repo>/
```

Keep `vcpkg/downloads`: same tarballs are reused by Linux vcpkg installs (minutes instead of downloads).

## 2. Quoting rule (avoid 20 min of shell pain)

`cmd.exe /c 'wsl -e bash -c "…"'` breaks on nested quotes and `$`/`||`. Always write a `.sh` file on the Windows side and run `wsl -e bash /mnt/c/.../x.sh`. Keep scripts idempotent; log to `/tmp/*.log` and `tail` on failure.

## 3. Configure and build

```bash
cd ~/<repo>
[ -x vcpkg/vcpkg ] || (cd vcpkg && ./bootstrap-vcpkg.sh -disableMetrics)
cmake --preset <preset>                       # e.g. ninja-multi-vcpkg
cmake --build builds/<preset> --config Release -j $(nproc)          # whole project
cmake --build builds/<preset> --config Release --target <one> -j $(nproc)
ctest --test-dir builds/<preset> -C Release --output-on-failure -j 8
```

`--target <one>` first: it compiles exactly the touched translation units and fails fast. Then the full build, because `struct` changes can break *other* TUs (e.g. added `unique_ptr` members make a type move-only).

## 4. Attribute test failures before fixing them

Compare against pristine sources, not against intuition:

```bash
git show "HEAD:src/path/File.hpp" > /mnt/c/.../pristine/src/path/File.hpp
# copy pristine files over the WSL copy, rebuild only the failing target, rerun
ctest -R <failing_test> --output-on-failure
```

- Fails on pristine too → pre-existing/environmental; say so, do not "fix" it.
- Passes on pristine → your change; bisect by file, then by hunk.

## 5. Test what has no test

Link a harness against the built library and assert equivalence to a brute-force reference:

```bash
g++ -std=c++20 -O2 -I src -I <lib-include-dirs> harness.cpp \
  -L <Release-dir> -l<lib> -Wl,-rpath,"$PWD/<Release-dir>:$PWD/<vendored lib dir>" -o /tmp/h
```

Cover: unique/duplicate/absent keys, random inputs vs brute force, boundary sizes, and the "fast path disabled" fallback.

## 6. Report the boundary explicitly

State what was proven (compiles, unit tests, harness) and what was not (e.g. a tool that must be `LD_PRELOAD`ed into a game binary cannot run here). Never imply an end-to-end run from a build plus unit tests.

## Pitfalls seen

- Uninitialized plain C aggregates (`struct { uintptr_t base; size_t size; }`) in a container struct: adding members changes stack layout and turns latent garbage reads into test failures. Value-initialize (`GumMemoryRange plt{};`).
- A shared library that also defines `main` may still be linked from a harness; constructors run though.
- Extra members that are `unique_ptr` vectors silently make a struct move-only: grep for by-value copies (`Type x = y`, returns, container storage) before assuming it compiles everywhere.
