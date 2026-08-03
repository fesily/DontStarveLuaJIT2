-- L-C client probe: log tokens for automated client inject smoke.
-- Prefix: [lc_probe] TOKEN NAME body
local _G = GLOBAL
local print = _G.print
local tostring = _G.tostring
local type = _G.type
local rawget = _G.rawget
local pcall = _G.pcall
local pairs = _G.pairs
local ipairs = _G.ipairs

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

-- Main LuaJit2 mod aliases (workshop + local folder names).
local MAIN_MOD_ALIASES = {
    "workshop-3444078585",
    "DontStarveLuaJit2",
    "DontStarveLuaJIT2",
}

local CONFIG_KEYS = {
    "NetworkOpt",
    "NetworkOptEntity",
    "EnableVBPool",
    "EnableNetSim",
    "EnableLagCompensation",
    "EnableForkSave",
    "EnableProfiler",
    "EnableTracy",
    "EnabledJIT",
    "AlwaysEnableMod",
}

local function find_main_modname()
    local KnownModIndex = rawget(_G, "KnownModIndex")
    if not KnownModIndex then
        return nil
    end
    for i = 1, #MAIN_MOD_ALIASES do
        local name = MAIN_MOD_ALIASES[i]
        local ok, enabled = pcall(function()
            return KnownModIndex:IsModEnabled(name) or KnownModIndex:IsModEnabledAny(name)
        end)
        if ok and enabled then
            return name
        end
    end
    -- fall back: any known_mods key matching alias prefix
    local ok, savedata = pcall(function()
        return KnownModIndex.savedata and KnownModIndex.savedata.known_mods
    end)
    if ok and type(savedata) == "table" then
        for i = 1, #MAIN_MOD_ALIASES do
            if savedata[MAIN_MOD_ALIASES[i]] then
                return MAIN_MOD_ALIASES[i]
            end
        end
    end
    return nil
end

local function options_to_map(options)
    local map = {}
    if type(options) ~= "table" then
        return map
    end
    for _, opt in pairs(options) do
        if type(opt) == "table" and type(opt.name) == "string" then
            local v = opt.saved
            if v == nil then
                v = opt.saved_client
            end
            if v == nil then
                v = opt.default
            end
            map[opt.name] = v
        end
    end
    return map
end

local function load_main_mod_config()
    local KnownModIndex = rawget(_G, "KnownModIndex")
    if not KnownModIndex then
        return nil, "no KnownModIndex"
    end
    local modname = find_main_modname()
    if not modname then
        return nil, "main mod not found"
    end
    local ok, options = pcall(function()
        return KnownModIndex:LoadModConfigurationOptions(modname, true)
            or KnownModIndex:LoadModConfigurationOptions(modname, false)
            or KnownModIndex:LoadModConfigurationOptions(modname)
    end)
    if not ok then
        return nil, "LoadModConfigurationOptions err: " .. tostring(options)
    end
    return options_to_map(options), modname
end

local function emit_config_samples()
    local map, info = load_main_mod_config()
    if not map then
        token("LG_CLIENT_CONFIG_ERR", tostring(info))
        return
    end
    token("LG_CLIENT_CONFIG_SRC", tostring(info))
    for i = 1, #CONFIG_KEYS do
        local k = CONFIG_KEYS[i]
        local v = map[k]
        token("LG_CLIENT_CONFIG", tostring(k) .. "=" .. tostring(v))
    end
end

AddGamePostInit(function()
    token("LG_CLIENT_MOD_LOADED", "probe_modmain")
    local gi = rawget(_G, "GameInjector")
    if gi ~= nil then
        token("LG_CLIENT_INJECT_OK", "GameInjector")
        token("LG_CLIENT_PLUGINS_OK", "inject_present")
    else
        token("LG_CLIENT_INJECT_MISSING", "GameInjector nil")
    end
    emit_config_samples()
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
            if _G.TheGlobalInstance and _G.TheGlobalInstance.DoTaskInTime then
                _G.TheGlobalInstance:DoTaskInTime(1, tick)
            end
        end
    end
    if _G.TheGlobalInstance and _G.TheGlobalInstance.DoTaskInTime then
        _G.TheGlobalInstance:DoTaskInTime(2, tick)
    end
end)
