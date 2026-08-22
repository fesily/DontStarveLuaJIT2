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

-- Private Host fields (additive; Host invokes `when` later with real ctx)
plugin_id = "network.rpc"
phases = "AfterModMain"   -- Lua face only; native face remains EarlyNative in C++ projection
depends = {}
soft_depends = {}
conflicts = {}
support_reload = false

configuration_options = {
    {
        name = "NetworkOpt",
        label = translate({ en = "Network RPC Optimizations", zh = "网络RPC优化" }),
        hover = translate({
            en = "Optimize network rpc transmission, out-of-order sending of RPCs, may have unexpected situations",
            zh = "优化网络RPC传输, 并行发送RPC, 可能导致意外的情况",
        }),
        options = toggle,
        default = true,
        disabled_value = false,
        disabled_by = disable_by_non_win,
        host_gate = true,
    },
}
