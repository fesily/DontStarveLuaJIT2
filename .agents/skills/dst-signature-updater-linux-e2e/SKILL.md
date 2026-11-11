---
name: dst-signature-updater-linux-e2e
description: "Verify DST signature_updater changes on Linux/WSL end-to-end: copy repo, vcpkg preset build, stage liblua51.so, run the LD_PRELOAD create target against the real game, validate signatures against the ELF, and A/B against pristine sources."
---

# DST signature_updater: Linux end-to-end + A/B verification

Goal: prove signature-generation changes on Linux (WSL) with the real game, and that
the generated DB is unchanged vs. pristine sources.

## 1. Prepare a WSL tree (ext4, excludes heavy/Windows-only dirs)

```bash
rsync -a --info=progress2 \
  --exclude .git --exclude builds --exclude vcpkg_installed --exclude .venv --exclude .steam \
  --exclude __pycache__ --exclude .pytest_cache \
  --exclude tools/angle --exclude tools/frida --exclude 3rd/angle --exclude 3rd/frida-gum-build \
  --exclude vcpkg/buildtrees --exclude vcpkg/packages --exclude vcpkg/installed --exclude vcpkg/.git \
  /mnt/c/<repo>/ ~/dontstarveluajit2/
```

Keep `vcpkg/downloads` (2 GB) — vcpkg reuses those tarballs, configure then takes ~15 s.

## 2. Configure

```bash
cd ~/dontstarveluajit2/vcpkg && ./bootstrap-vcpkg.sh -disableMetrics
```

`cmake/GameDir.cmake` is generated and copied from Windows; overwrite it from a
**single-quoted heredoc** (the apostrophe in `Don't Starve Together` breaks printf
quoting — a bad quote silently writes `set(GAME_DIR "")`):

```bash
cat > cmake/GameDir.cmake <<'EOF'
set(GAME_DIR "/home/<user>/.steam/debian-installation/steamapps/common/Don't Starve Together")
EOF
cmake --preset ninja-multi-vcpkg
```

## 3. Stage the Linux training Lua + tool deps

```bash
cp Mod/bin64/linux/lib64/liblua51.so Mod/deps/liblua51.so
cp Mod/bin64/linux/lib64/lua51        Mod/deps/lua51
```

`LUA51_PATH = Mod/deps/liblua51.so`; without it the tool's `pre_updater()` cannot load
the training module.

## 4. Run create (tool is LD_PRELOADed into the game)

```bash
cp Mod/signatures_client.json Mod/signatures_server.json /tmp/sigbak/   # repo ships Windows DBs
cmake --build builds/ninja-multi-vcpkg --config Release --target create
```

On Linux `signature_updater` is a `.so`; its constructor checks the main-module name
contains `dontstarve`, reads `SIGNATURE_TOOL_MODE`, hooks Steam init and runs
`pre_updater()+update()` in a thread. Both game binaries run headless; RC=0 means both
DBs were written.

## 5. Independent validation (do not trust the tool alone)

Python: parse ELF64 section headers, locate `.text`, then for every entry require
**exactly one** pattern hit inside `[lua_base, text_end]` and that
`hit_vaddr + pattern_offset - offset` is the **same base for all entries**.
Derive the base first from unambiguous entries, then rescan from it.
Observed Linux bases: client `0x4aad50`, server `0x41ef90`; 102 entries each
(stock `liblua51.so` exports neither `lua_setfuncchunkname` nor `lua_getfuncchunkname`).

## 6. A/B against pristine sources

```bash
mkdir -p /tmp/pristine/src/FunctionRelocation
for f in ModuleSections.hpp ModuleSections.cpp FunctionTable.hpp Signature.cpp NucleusAdapter.cpp; do
  git -C /mnt/c/<repo> show HEAD:src/FunctionRelocation/$f > /tmp/pristine/src/FunctionRelocation/$f
done
# copy pristine over -> rebuild signature_updater -> run create -> save to /tmp/baseline
# restore changed files -> rebuild -> run create -> save to /tmp/optimized
diff via json: entries + per-name dict equality
```

Keep `DontStarveSignature.cpp` (phase timing logs) in both builds so the phase lines in
the create output are comparable: pre-`scan_features` = nucleus work,
`phase[0] -> phase[1]` gap = per-export resolution.

## Pitfalls seen

- **Uninitialized `GumMemoryRange`**: `ModuleSections.text/pdata/rodata/plt/got_plt/bss/ehframe`
  had no initializer, so `in_plt()/in_got_plt()` read stack garbage; a size change in the
  struct flipped `test_xref_pattern` to abort. Fix: value-initialize `{}` (also
  `ModuleDetials::range`).
- **ModuleSections is move-only** after adding `std::vector<std::unique_ptr<...>>` caches;
  all uses are refs/out-params, but check Linux-only TUs compile.
- **Never test `create` on a copy and leave Linux DBs in place**: the JSON has no platform
  tag. Back up, and restore the repo's DBs afterwards.
- Release vs Debug matters: Debug `nucleus_disasm` is ~8x slower (26.8 s vs 3.3 s per game
  binary); the tool binary used for timing must be Release.
