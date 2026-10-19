local G = GLOBAL
AddSimPostInit(function()
    local vm = G.GameInjector and G.GameInjector.DS_LUAJIT_get_vm_type_name(0) or "unknown"
    G.print("[ds_perf] SERVER_WORLD_READY vm=" .. G.tostring(vm))
end)
