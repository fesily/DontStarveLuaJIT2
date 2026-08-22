# External pack fixture

Minimal enabled-mod layout for manual/CI discovery tests.

- Root `modinfo.lua` sets `luajit_plugin_pack` + `plugin_id`.
- Optional package under `plugins/plugin_example/`.
- No real DLL (native load tests use temp trees).
