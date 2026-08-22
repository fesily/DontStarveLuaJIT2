-- L-C client probe: log tokens for automated client inject smoke.
-- Prefix: [lc_probe] TOKEN NAME body
local _G = GLOBAL
local print = _G.print
local tostring = _G.tostring
local tonumber = _G.tonumber
local type = _G.type
local rawget = _G.rawget
local pcall = _G.pcall
local pairs = _G.pairs
local ipairs = _G.ipairs

local function token(name, body)
    print("[lc_probe] TOKEN " .. name .. " " .. (body or "1"))
end

-- Host-mode helpers (LC_HOST_MODE=1): StartServer + LOAD_SLOT, no LAN join.
local function env_flag(name)
    local v = rawget(_G, "os") and _G.os.getenv and _G.os.getenv(name)
    return v == "1" or v == "true" or v == "TRUE"
end

local function host_slot()
    local v = rawget(_G, "os") and _G.os.getenv and _G.os.getenv("LC_HOST_SLOT")
    local n = tonumber(v or "1") or 1
    if n < 1 then n = 1 end
    return n
end

local world_ready_emitted = false
local host_started = false
local host_ok_emitted = false

local function emit_host_ok(reason)
    if host_ok_emitted then
        return
    end
    host_ok_emitted = true
    local TheNet = rawget(_G, "TheNet")
    local TheWorld = rawget(_G, "TheWorld")
    local hosted = false
    local mastersim = false
    pcall(function()
        if TheNet and TheNet.GetServerIsClientHosted then
            hosted = TheNet:GetServerIsClientHosted() and true or false
        end
    end)
    pcall(function()
        if TheWorld then mastersim = TheWorld.ismastersim and true or false end
    end)
    if hosted or mastersim then
        token("LG_CLIENT_HOST_OK", tostring(reason or "host") .. " hosted=" .. tostring(hosted) .. " mastersim=" .. tostring(mastersim))
    else
        token("LG_CLIENT_HOST_FAIL", "not_client_hosted reason=" .. tostring(reason))
    end
end

local function emit_world_ready(reason)
    if world_ready_emitted then
        return
    end
    world_ready_emitted = true
    token("LG_CLIENT_WORLD_READY", reason or "world")
    if env_flag("LC_HOST_MODE") then
        emit_host_ok(reason)
    end
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

local function offline_serverdata()
    local GetDefaultServerData = rawget(_G, "GetDefaultServerData")
    local sd = nil
    if type(GetDefaultServerData) == "function" then
        local ok, ret = pcall(GetDefaultServerData)
        if ok and type(ret) == "table" then
            sd = ret
        end
    end
    if type(sd) ~= "table" then
        sd = {
            pvp = false,
            game_mode = "survival",
            online_mode = false,
            max_players = 6,
            name = "LC Host Smoke",
            password = "",
            description = "plugin_lc_probe empty-slot host",
        }
    end
    sd.online_mode = false
    if sd.name == nil or sd.name == "" then
        sd.name = "LC Host Smoke"
    end
    return sd
end

local function try_start_host()
    if host_started then
        return
    end
    if not env_flag("LC_HOST_MODE") then
        return
    end
    host_started = true

    local TheNet = rawget(_G, "TheNet")
    local ShardSaveGameIndex = rawget(_G, "ShardSaveGameIndex")
    local KnownModIndex = rawget(_G, "KnownModIndex")
    local StartNextInstance = rawget(_G, "StartNextInstance")
    local RESET_ACTION = rawget(_G, "RESET_ACTION")
    local DisableAllDLC = rawget(_G, "DisableAllDLC")
    local TheSim = rawget(_G, "TheSim")

    if not TheNet or not ShardSaveGameIndex or not StartNextInstance or not RESET_ACTION then
        token("LG_CLIENT_HOST_FAIL", "missing_globals")
        return
    end

    local slot = host_slot()
    -- LC_HOST_SLOT=new|0 → first free local slot (empty worldgen path).
    local slot_env = rawget(_G, "os") and _G.os.getenv and _G.os.getenv("LC_HOST_SLOT")
    if slot_env == "new" or slot_env == "0" then
        local ok_new, new_slot = pcall(function()
            return ShardSaveGameIndex:GetNextNewSlot("local")
        end)
        if ok_new and type(new_slot) == "number" and new_slot >= 1 then
            slot = new_slot
        end
    end

    token("LG_CLIENT_HOST_BEGIN", "slot=" .. tostring(slot))

    local ok_inv, TheInventory = pcall(function() return rawget(_G, "TheInventory") end)
    if ok_inv and TheInventory then
        pcall(function()
            if TheInventory.HasSupportForOfflineSkins and TheInventory:HasSupportForOfflineSkins()
                and TheInventory.HasDownloadedInventory and not TheInventory:HasDownloadedInventory()
                and TheInventory.ForceLoadOfflineCache then
                TheInventory:ForceLoadOfflineCache()
            end
        end)
    end

    pcall(function()
        if ShardSaveGameIndex.LoadSlotEnabledServerMods then
            ShardSaveGameIndex:LoadSlotEnabledServerMods()
        end
        if KnownModIndex and KnownModIndex.Save then
            KnownModIndex:Save()
        end
    end)

    -- Optional: wipe slot for deterministic empty-slot worldgen tests.
    if env_flag("LC_HOST_FORCE_EMPTY") then
        token("LG_CLIENT_HOST_FORCE_EMPTY", "slot=" .. tostring(slot))
        pcall(function()
            ShardSaveGameIndex:DeleteSlot(slot, function() end, false)
        end)
        if TheSim and TheSim.EnsureShardIndexPathExists then
            pcall(function() TheSim:EnsureShardIndexPathExists(slot) end)
        end
    end

    local empty = false
    pcall(function()
        empty = ShardSaveGameIndex:IsSlotEmpty(slot) and true or false
    end)

    local function finish_load(tag)
        pcall(function()
            if DisableAllDLC then DisableAllDLC() end
        end)
        local ok_next, err = pcall(function()
            StartNextInstance({ reset_action = RESET_ACTION.LOAD_SLOT, save_slot = slot })
        end)
        if not ok_next then
            token("LG_CLIENT_HOST_FAIL", "StartNextInstance:" .. tostring(err))
            return
        end
        token("LG_CLIENT_HOST_STARTED", "slot=" .. tostring(slot) .. " " .. tostring(tag or "load"))
    end

    if empty then
        token("LG_CLIENT_HOST_EMPTY_SLOT", "slot=" .. tostring(slot))
        local serverdata = offline_serverdata()

        -- Create Master shard index if missing, write default world options, then LOAD_SLOT.
        -- Mirrors ServerCreationScreen empty-slot SetServerShardData → LOAD_SLOT (single level).
        local master = nil
        pcall(function()
            master = ShardSaveGameIndex:GetShardIndex(slot, "Master", true)
        end)
        if not master or not master.SetServerShardData then
            token("LG_CLIENT_HOST_FAIL", "empty_no_master_shard")
            return
        end

        local started = false
        local ok_start, ret = pcall(function()
            return TheNet:StartServer(false, slot, serverdata)
        end)
        started = ok_start and ret and true or false
        if not started then
            token("LG_CLIENT_HOST_FAIL", "StartServer_false_empty")
            return
        end

        local ok_set, set_err = pcall(function()
            master:SetServerShardData(nil, serverdata, function()
                finish_load("empty_worldgen")
            end)
        end)
        if not ok_set then
            token("LG_CLIENT_HOST_FAIL", "SetServerShardData:" .. tostring(set_err))
            return
        end
        return
    end

    local serverdata = nil
    pcall(function()
        serverdata = ShardSaveGameIndex:GetSlotServerData(slot)
    end)

    local started = false
    local ok_start, ret = pcall(function()
        return TheNet:StartServer(false, slot, serverdata)
    end)
    started = ok_start and ret and true or false

    if not started then
        token("LG_CLIENT_HOST_FAIL", "StartServer_false")
        return
    end

    finish_load("existing")
end

-- Host-only auto-spawn (stress bot Part 2 only; no LAN search).
local original_ResumeRequestLoadComplete = nil
local spawn_pending = false

local function host_send_spawn_request()
    local TheNet = rawget(_G, "TheNet")
    if not TheNet or not TheNet.SendSpawnRequestToServer then
        return
    end
    local char = "wilson"
    local skin = char .. "_none"
    pcall(function()
        TheNet:SendSpawnRequestToServer(char, skin, "", "", "", "", {}, nil)
    end)
end

local function hooked_ResumeRequestLoadComplete(success)
    if success then
        if original_ResumeRequestLoadComplete then
            original_ResumeRequestLoadComplete(success)
        end
        return
    end

    local TheNet = rawget(_G, "TheNet")
    if TheNet and TheNet.DeleteUserSession and TheNet.GetUserID then
        pcall(function()
            TheNet:DeleteUserSession(TheNet:GetUserID())
        end)
    end

    if spawn_pending then
        return
    end
    spawn_pending = true

    local TheWorld = rawget(_G, "TheWorld")
    if TheWorld and TheWorld.DoTaskInTime then
        TheWorld:DoTaskInTime(1, function()
            spawn_pending = false
            host_send_spawn_request()
        end)
    else
        spawn_pending = false
        host_send_spawn_request()
    end
end

if env_flag("LC_HOST_MODE") then
    AddClassPostConstruct("screens/redux/mainscreen", function(self)
        self.inst:DoTaskInTime(1, function()
            try_start_host()
        end)
    end)

    AddGamePostInit(function()
        original_ResumeRequestLoadComplete = rawget(_G, "ResumeRequestLoadComplete")
        _G.rawset(_G, "ResumeRequestLoadComplete", hooked_ResumeRequestLoadComplete)
    end)
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
