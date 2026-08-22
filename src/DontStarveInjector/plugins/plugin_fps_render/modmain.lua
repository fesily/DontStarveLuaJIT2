-- plugins/plugin_fps_render/modmain.lua
-- TargetRenderFPS → DS_LUAJIT_set_target_fps + SetNetbookMode.
-- Non-Windows GetModConfigData returns nil (HookGetModConfigData).

local injector = GameInjector
if not injector then
    return
end

local targetfps
if type(GetModConfigData) == "function" then
    targetfps = GetModConfigData("TargetRenderFPS")
end
if not targetfps then
    return
end
if injector.DS_LUAJIT_set_target_fps(targetfps, 1) > 0 then
    print("Reset fps by SetNetbookMode", targetfps)
    TheSim:SetNetbookMode(false)
end
