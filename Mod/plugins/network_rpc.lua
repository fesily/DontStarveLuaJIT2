-- Lua face of dual-face plugin network.rpc (native EarlyNative installs GameNetWorkHookRpc4).
-- Mirrors former modmain NetWorkOpt RPC channel machinery when NetworkOpt is on.
-- Priority 40 per architecture inventory §7.3.

return {
    id = "network.rpc",
    version = "1.0.0",
    depends = {},
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    options = { all_of = { "NetworkOpt" } },
    support_reload = false,
    priority = 40,
    load = function(ctx)
        local injector = ctx and ctx.injector
        if not injector then
            return
        end

        local net_mt = getmetatable(TheNet).__index
        local default_packetPriority = 1 -- PacketPriority::HIGH_PRIORITY
        local default_reliability = 3 -- PacketReliability::RELIABLE_ORDERED
        local old_SendRPCToServer = net_mt.SendRPCToServer
        local old_SendRPCToClient = net_mt.SendRPCToClient
        local old_SendRPCToShard = net_mt.SendRPCToShard
        local old_SendModRPCToServer = net_mt.SendModRPCToServer
        local old_SendModRPCToClient = net_mt.SendModRPCToClient
        local old_SendModRPCToShard = net_mt.SendModRPCToShard

        local _FNV_offset_basis = 2166136261
        local _FNV_prime = 16777619
        local function hash_string(data)
            assert(type(data) == "string")
            local hash = _FNV_offset_basis
            for i = 1, #data do
                hash = bit.bxor(hash, data:byte(i))
                hash = hash * _FNV_prime
            end
            return hash
        end

        local function alloc_rpc_channel(namespace_or_code, id)
            if type(namespace_or_code) == "number" then
                return namespace_or_code % 32
            end
            local hash = hash_string(namespace_or_code)
            hash = bit.bxor(hash, id + 0x9e3779b9 + bit.lshift(hash, 6) + bit.rshift(hash, 2))
            return hash % 32
        end

        local mod_namespace_id_channel = {}
        local function get_mod_channel(namespace, id)
            mod_namespace_id_channel[namespace] = mod_namespace_id_channel[namespace] or {}
            local mod_namespace = mod_namespace_id_channel[namespace]
            if mod_namespace[id] == nil then
                mod_namespace[id] = alloc_rpc_channel(namespace, id)
            end
            return mod_namespace[id]
        end

        net_mt.alloc_rpc_channel = alloc_rpc_channel

        function net_mt:SendRPCToServer2(code, packetPriority, reliability, channel, ...)
            packetPriority = packetPriority or default_packetPriority
            reliability = reliability or default_reliability
            channel = channel or alloc_rpc_channel(code)
            injector.DS_LUAJIT_SetNextRpcInfo(packetPriority, reliability, channel)
            return old_SendRPCToServer(self, code, ...)
        end

        function net_mt:SendRPCToClient2(code, packetPriority, reliability, channel, ...)
            packetPriority = packetPriority or default_packetPriority
            reliability = reliability or default_reliability
            channel = channel or alloc_rpc_channel(code)
            injector.DS_LUAJIT_SetNextRpcInfo(packetPriority, reliability, channel)
            return old_SendRPCToClient(self, code, ...)
        end

        function net_mt:SendRPCToShard2(code, packetPriority, reliability, channel, ...)
            packetPriority = packetPriority or default_packetPriority
            reliability = reliability or default_reliability
            channel = channel or alloc_rpc_channel(code)
            injector.DS_LUAJIT_SetNextRpcInfo(packetPriority, reliability, channel)
            return old_SendRPCToShard(self, code, ...)
        end

        function net_mt:SendModRPCToServer2(id_table, packetPriority, reliability, channel, ...)
            packetPriority = packetPriority or default_packetPriority
            reliability = reliability or default_reliability
            channel = channel or get_mod_channel(id_table.namespace, id_table.id)
            injector.DS_LUAJIT_SetNextRpcInfo(packetPriority, reliability, channel)
            return old_SendModRPCToServer(self, id_table.namespace, id_table.id, ...)
        end

        function net_mt:SendModRPCToClient2(id_table, packetPriority, reliability, channel, ...)
            packetPriority = packetPriority or default_packetPriority
            reliability = reliability or default_reliability
            channel = channel or get_mod_channel(id_table.namespace, id_table.id)
            injector.DS_LUAJIT_SetNextRpcInfo(packetPriority, reliability, channel)
            return old_SendModRPCToClient(self, id_table.namespace, id_table.id, ...)
        end

        function net_mt:SendModRPCToShard2(id_table, packetPriority, reliability, channel, ...)
            packetPriority = packetPriority or default_packetPriority
            reliability = reliability or default_reliability
            channel = channel or get_mod_channel(id_table.namespace, id_table.id)
            injector.DS_LUAJIT_SetNextRpcInfo(packetPriority, reliability, channel)
            return old_SendModRPCToShard(self, id_table.namespace, id_table.id, ...)
        end

        -- NetworkOpt on: wrap stock SendRPC* with channel selection via SetNextRpcInfo.
        function net_mt:SendRPCToServer(code, ...)
            local c_channel = alloc_rpc_channel(code)
            injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
            return old_SendRPCToServer(self, code, ...)
        end

        function net_mt:SendRPCToClient(code, ...)
            local c_channel = alloc_rpc_channel(code)
            injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
            return old_SendRPCToClient(self, code, ...)
        end

        function net_mt:SendRPCToShard(code, ...)
            local c_channel = alloc_rpc_channel(code)
            injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
            return old_SendRPCToShard(self, code, ...)
        end

        function net_mt:SendModRPCToServer(namespace, id, ...)
            local c_channel = get_mod_channel(namespace, id)
            injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
            return old_SendModRPCToServer(self, namespace, id, ...)
        end

        function net_mt:SendModRPCToClient(namespace, id, ...)
            local c_channel = get_mod_channel(namespace, id)
            injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
            return old_SendModRPCToClient(self, namespace, id, ...)
        end

        function net_mt:SendModRPCToShard(namespace, id, ...)
            local c_channel = get_mod_channel(namespace, id)
            injector.DS_LUAJIT_SetNextRpcInfo(nil, nil, c_channel)
            return old_SendModRPCToShard(self, namespace, id, ...)
        end
    end,
    unload = function(ctx)
        -- Sticky by default; TheNet metatable wraps are not torn down.
    end,
}
