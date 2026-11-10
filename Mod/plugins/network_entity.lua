-- Lua face of network.entity. Depends on network.rpc (native EarlyNative installs
-- GameNetWorkHookRpc4 entity serialize hooks; Lua face registers SpawnPrefab extension).
-- Mirrors former modmain NetworkOptEntity SpawnPrefab wrap.
-- Priority 40 per architecture inventory §7.3.

return {
    id = "network.entity",
    version = "1.0.0",
    depends = { "network.rpc" },
    soft_depends = {},
    conflicts = {},
    phases = "AfterModMain",
    options = { all_of = { "NetworkOptEntity" } },
    support_reload = false,
    priority = 40,
    load = function(ctx)
        local injector = ctx and ctx.injector
        if not injector then
            return
        end
        -- Same dynamic module as network.rpc: without it the first networked
        -- prefab would call a nil export and abort world start.
        if type(injector.DS_LUAJIT_EntityNetWorkExtension_Register) ~= "function" then
            print("[luajit][plugin] network.entity: DS_LUAJIT_EntityNetWorkExtension_Register missing (native plugin_network_rpc not loaded); SpawnPrefab wrap skipped")
            return
        end

        local old_SpawnPrefab = SpawnPrefab
        function SpawnPrefab(...)
            local inst = old_SpawnPrefab(...)
            if inst and inst.Network and not inst.NetworkExtension then
                inst.NetworkExtension = injector.DS_LUAJIT_EntityNetWorkExtension_Register(
                    inst.Network,
                    inst.Network:GetNetworkID()
                )
            end
            return inst
        end
    end,
    unload = function(ctx)
        -- Sticky by default; SpawnPrefab wrap is not torn down.
    end,
}
