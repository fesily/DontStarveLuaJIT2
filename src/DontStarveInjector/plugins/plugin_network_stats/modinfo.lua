-- plugins/plugin_network_stats/modinfo.lua
-- Safe under engine sandbox: data + function defs only (no TheNet at top-level).

-- Engine-required / compatibility (DST InitializeModInfo)
name = "Network Stats"
description = "Per-client RTT read from the engine and exposed to Lua (feature package)."
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
priority = 42

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "network.stats"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

configuration_options = {
    {
        name = "EnableClientPing",
        label = translate({ en = "Client ping (per-client RTT)", zh = "客户端延迟(每客户端RTT)" }),
        hover = translate({
            en = "Read each client's round-trip time from the engine and expose it to Lua "
                 .. "(network.stats plugin, Windows/Linux x64).",
            zh = "从引擎读取每个客户端的往返延迟并暴露给 Lua（network.stats 插件，Windows/Linux x64）。",
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_non_x64,
        host_gate = true,
        require_restart = true,
    },
}
