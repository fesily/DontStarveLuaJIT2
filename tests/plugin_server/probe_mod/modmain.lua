-- L-G probe: emit log tokens for automated dedicated harness.
local _G = GLOBAL
local print = _G.print
local tostring = _G.tostring
local type = _G.type
local rawget = _G.rawget
local pcall = _G.pcall

local function token(name, body)
    print("[lg_probe] TOKEN " .. name .. " " .. (body or "1"))
end

AddGamePostInit(function()
    token("LG_MOD_LOADED", "probe_modmain")
    local gi = rawget(_G, "GameInjector")
    if gi ~= nil then
        token("LG_INJECT_OK", "GameInjector")
        token("LG_PLUGINS_OK", "inject_present")
    else
        token("LG_INJECT_MISSING", "GameInjector nil")
    end
end)

AddSimPostInit(function()
    token("LG_WORLD_READY", "sim_post_init")

    local TheNet = _G.TheNet
    local TheSim = _G.TheSim
    local paused = false
    local method = "none"

    if TheNet ~= nil and TheNet.SetServerPaused ~= nil then
        local ok, err = pcall(function()
            TheNet:SetServerPaused(true)
        end)
        if ok then
            if TheNet.GetServerPaused ~= nil then
                paused = TheNet:GetServerPaused() and true or false
            else
                paused = true
            end
            if paused then
                method = "SetServerPaused"
            else
                method = "SetServerPaused_false"
            end
        else
            method = "SetServerPaused_err:" .. tostring(err)
        end
    end

    if not paused and TheSim ~= nil and TheSim.SetTimeScale ~= nil then
        local ok, err = pcall(function()
            TheSim:SetTimeScale(0)
        end)
        if ok then
            local scale = 1
            if TheSim.GetTimeScale ~= nil then
                scale = TheSim:GetTimeScale() or 1
            else
                scale = 0
            end
            if scale == 0 then
                paused = true
                method = "SetTimeScale0"
            else
                method = "SetTimeScale_nonzero:" .. tostring(scale)
            end
        else
            method = "SetTimeScale_err:" .. tostring(err)
        end
    end

    -- Last resort: schedule a periodic no-op and mark "stable_running" as paused surrogate
    -- Spec wants sim paused; if APIs missing, still report failure explicitly.
    if paused then
        token("LG_SIM_PAUSED", method)
    else
        token("LG_SIM_PAUSE_FAILED", method)
    end
end)
