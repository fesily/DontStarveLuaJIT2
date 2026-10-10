-- plugins/plugin_network_stats/modmain.lua
-- Expose the native per-client RTT (network.stats) as TheNet:GetClientPing.

local injector = GameInjector
if not injector then
    return
end

local net = TheNet
local net_mt = net and getmetatable(net) and getmetatable(net).__index
if not net_mt then
    return
end

-- Returns the client's round-trip time in milliseconds, or -1 when unknown
-- (feature disabled / client not seen yet).
function net_mt:GetClientPing(userid)
    if type(userid) ~= "string" or not injector.DS_LUAJIT_net_client_ping then
        return -1
    end
    return injector.DS_LUAJIT_net_client_ping(userid)
end
