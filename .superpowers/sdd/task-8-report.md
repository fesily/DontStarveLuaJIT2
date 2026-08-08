# Task 8 Report: Manifest zip includes package Lua + docs cutover (P4)

**Status:** DONE  
**Branch:** `feature/plugin-package-aggregation`

## Commits

| SHA | Message |
|-----|---------|
| `2711e09` | `docs+tools: package layout manifest zips and dual-face checklist` |

Full SHA: `2711e09` (see `git rev-parse 2711e09`)  
Base: `9492535` (Task 7 report)

## Changes

| Action | Path |
|--------|------|
| Modify | `tools/gen_plugins_manifest.py` — `iter_plugin_modules` package-subdir discovery; zip members package-relative (`modinfo.lua`, `modmain.lua`, `scripts/**`); meta next to module |
| Modify | `tests/plugin/test_gen_plugins_manifest.py` — package-subdir fixture asserts zip + `files[]` include Lua |
| Modify | `docs/plugin-system.md` — §3.4 dual-face package how-to; §7 examples; §9 checklist; key paths |

Identity codegen (`gen_plugin_identity.py` / `*_identity.inc`) **not** shipped this slice; docs note hand-sync + gate, regen later OK.

## Tests

```bash
python tests/plugin/test_gen_plugins_manifest.py -q
# 3/3 OK (flat + package + merge)

python tools/check_plugin_package_identity.py --source-root .
# identity gate OK: checked=6 skipped=0  (IDENTITY_RC:0)

python tests/plugin/test_plugin_package_identity.py -q
# 6/6 OK

python tests/plugin/run_package_load.py
# ALL PASS package_load_spec  (PKG_RC:0)

LUA_BIN=<parent builds>/luajit/Release/luajit.exe python tests/plugin/run_lua_host.py
# plugin_host_lua_spec: all tests passed  (HOST_RC:0)

python tools/gen_plugins_manifest.py --help  # HELP_RC:0
```

No full suite / formatters (per task scope). L-G not run.

## Cutover greps

```text
rg load_flat("(save_fork|network_rpc|…)") Mod/plugins/init.lua → none
Mod/plugins/{save_fork,network_rpc,network_sim,sim_lagcomp,debug_profiler,fps_render}.lua → gone
Mod/scripts/{fork_save,netsim,lag_compensation}.lua → gone
```

## Concerns

1. **plugin.manager apply still flat-basename:** zips now list nested `scripts/...` and package Lua; `PluginZipExtract` / `PluginApply` still reject nested paths / require flat basenames. Spec marks full mini-mod manager apply as follow-up — download apply of dual-face package zips will need a later allowlist/install update.
2. **Identity codegen deferred:** native still hand-syncs `man.id`/`version`/option keys; CI gate covers drift. Optional `plugin_*_identity.inc` regen can land later.
3. **Dual tree mirror** (`src/.../plugin_*` vs `Mod/plugins/plugin_*`) unchanged from Task 6/7 until install is sole runtime path.
