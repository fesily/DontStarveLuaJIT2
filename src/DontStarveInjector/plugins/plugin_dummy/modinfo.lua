-- DST mini-mod / external pack face for debug.dummy
name = "LuaJIT Plugin Dummy"
description = "Smoke external luajit_plugin_pack for DontStarveLuaJit2 (debug.dummy)."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = false
server_only_mod = false
all_clients_require_mod = false

priority = 1000

-- External discovery marker (required for packs outside DontStarveLuaJit2)
luajit_plugin_pack = true
plugin_id = "debug.dummy"

phases = "AfterModMain"
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
-- No options: treated as always eligible when pack is enabled
