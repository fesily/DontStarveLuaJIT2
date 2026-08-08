-- plugins/plugin_network_rpc/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Network RPC"
description = "RPC channel selection for DontStarveLuaJit2 (feature package)."
author = "fesil"
version = "1.0.0"
api_version = 10

dont_starve_compatible = false
reign_of_giants_compatible = false
dst_compatible = true

client_only_mod = false
server_only_mod = false
all_clients_require_mod = false

-- Optional engine
priority = 40
-- configuration_options = nil  -- embedded: UI on parent Mod; standalone may fill later

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "network.rpc"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false
options = { all_of = { "NetworkOpt" } }
