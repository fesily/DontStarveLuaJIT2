local G = GLOBAL
G.DSPerfStartup("MODMAIN")
AddGamePostInit(function()
    G.DSPerfStartup("GAME_POSTINIT")
end)
AddSimPostInit(function()
    G.DSPerfStartup("SIM_POSTINIT")
    local count = 0
    for _ in G.pairs(G.Ents) do count = count + 1 end
    G.print("[ds_perf] SAVE_LOADED entities=" .. count
        .. " cycles=" .. G.tostring(G.TheWorld.state.cycles))
end)
