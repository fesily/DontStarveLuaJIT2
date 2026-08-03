-- L-C client probe: log tokens for automated client inject smoke.
-- Prefix: [lc_probe] TOKEN NAME body
local _G = GLOBAL
local print = _G.print
local tostring = _G.tostring
local type = _G.type
local rawget = _G.rawget
local pcall = _G.pcall

local function token(name, body)
    print("[lc_probe] TOKEN " .. name .. " " .. (body or "1"))
end

local world_ready_emitted = false

local function emit_world_ready(reason)
    if world_ready_emitted then
        return
    end
    world_ready_emitted = true
    token("LG_CLIENT_WORLD_READY", reason or "world")
end

AddGamePostInit(function()
    token("LG_CLIENT_MOD_LOADED", "probe_modmain")
    local gi = rawget(_G, "GameInjector")
    if gi ~= nil then
        token("LG_CLIENT_INJECT_OK", "GameInjector")
        -- Phase-1: inject present is the structured plugins-ok signal (host lives in LuaJit2).
        token("LG_CLIENT_PLUGINS_OK", "inject_present")
    else
        token("LG_CLIENT_INJECT_MISSING", "GameInjector nil")
    end
end)

AddSimPostInit(function()
    emit_world_ready("sim_post_init")
end)

AddPlayerPostInit(function(player)
    if player ~= nil then
        emit_world_ready("player_post_init")
    end
end)

-- Fallback poll: InGamePlay / ThePlayer after FE
AddGamePostInit(function()
    local TheWorld = nil
    local tries = 0
    local function tick()
        tries = tries + 1
        local ok, in_play = pcall(function()
            if type(_G.InGamePlay) == "function" then
                return _G.InGamePlay()
            end
            return false
        end)
        local player = rawget(_G, "ThePlayer")
        if (ok and in_play) or player ~= nil then
            emit_world_ready(player ~= nil and "theplayer" or "ingameplay")
            return
        end
        if tries < 120 then
            -- ~2 minutes at 1s if scheduler available
            if _G.TheGlobalInstance and _G.TheGlobalInstance.DoTaskInTime then
                _G.TheGlobalInstance:DoTaskInTime(1, tick)
            end
        end
    end
    if _G.TheGlobalInstance and _G.TheGlobalInstance.DoTaskInTime then
        _G.TheGlobalInstance:DoTaskInTime(2, tick)
    end
end)
