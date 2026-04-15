---@diagnostic disable: lowercase-global, undefined-global
_G = GLOBAL

local LOG_PREFIX = "[StressBot]"

local function log(...)
    print(LOG_PREFIX, ...)
end

local auto_spawn_character = GetModConfigData("auto_spawn_character") or "wilson"
local auto_spawn_delay = GetModConfigData("auto_spawn_delay") or 1

local DST_CHARACTERS = {
    "wilson", "willow", "wolfgang", "wendy", "wx78",
    "wickerbottom", "woodie", "wes", "waxwell",
}

local function pick_character()
    if auto_spawn_character == "random" then
        return DST_CHARACTERS[math.random(#DST_CHARACTERS)]
    end
    return auto_spawn_character
end

local function send_spawn_request()
    local char = pick_character()
    local skin = char .. "_none"
    log("Sending spawn request: character=" .. char .. ", skin=" .. skin)
    _G.TheNet:SendSpawnRequestToServer(char, skin, "", "", "", "", {}, nil)
end

------------------------------------------------------------------------
-- Part 1: Auto-connect via LAN server discovery
--
-- We hook MainScreen (the primary screen shown on game start) so that
-- when it opens, we start a LAN server search, find the first available
-- server, and join it via JoinServer() (which uses
-- TheNet:JoinServerResponse -- the path that bypasses the C++ version
-- check broken by AppVersionDevPatch).
--
-- We hook MainScreen (not MultiplayerMainScreen) because:
--   1. MainScreen is the FIRST screen shown on launch
--   2. MultiplayerMainScreen shows a "Mods installed!" warning popup
--      that blocks auto-connect
--   3. No need to go through the Play → login → secondary menu flow
--
-- +connect is NOT used because it goes through TheNet:StartClient which
-- performs a strict version check at the RakNet layer.
------------------------------------------------------------------------

local auto_connect_done = false

local LAN_SEARCH_INTERVAL = 1
local LAN_SEARCH_TIMEOUT  = 30

local function try_auto_connect(screen_inst)
    if auto_connect_done then return end
    auto_connect_done = true

    log("Starting LAN server search for auto-connect...")
    _G.TheNet:SearchLANServers(false)

    local elapsed = 0
    local function poll()
        elapsed = elapsed + LAN_SEARCH_INTERVAL

        if _G.TheNet:GetServerListingReadDirty() then
            local listings = _G.TheNet:GetServerListings()
            if listings and #listings > 0 then
                local server = listings[1]
                log("Found LAN server: " .. tostring(server.name)
                    .. " (guid=" .. tostring(server.guid) .. ")")
                _G.JoinServer(server)
                return
            end
        end

        if elapsed >= LAN_SEARCH_TIMEOUT then
            log("ERROR: LAN server search timed out after " .. LAN_SEARCH_TIMEOUT .. "s")
            auto_connect_done = false  -- allow retry
            return
        end

        screen_inst.inst:DoTaskInTime(LAN_SEARCH_INTERVAL, poll)
    end

    screen_inst.inst:DoTaskInTime(LAN_SEARCH_INTERVAL, poll)
end

AddClassPostConstruct("screens/redux/mainscreen", function(self)
    log("MainScreen opened, scheduling auto-connect")
    self.inst:DoTaskInTime(0.5, function()
        try_auto_connect(self)
    end)
end)

------------------------------------------------------------------------
-- Part 2: Auto-spawn after connecting to the server
--
-- Override mainfunctions.lua:2027 ResumeRequestLoadComplete
-- success=true: existing session → call original (auto-rejoin)
-- success=false: new player → skip LobbyScreen, send spawn request
------------------------------------------------------------------------

local original_ResumeRequestLoadComplete = nil
local spawn_pending = false

local function hooked_ResumeRequestLoadComplete(success)
    if success then
        log("Existing session detected, auto-rejoining")
        if original_ResumeRequestLoadComplete then
            original_ResumeRequestLoadComplete(success)
        end
        return
    end

    log("New player session, auto-spawning in " .. auto_spawn_delay .. "s")
    _G.TheNet:DeleteUserSession(_G.TheNet:GetUserID())

    if spawn_pending then
        return
    end
    spawn_pending = true

    if auto_spawn_delay > 0 then
        _G.TheWorld:DoTaskInTime(auto_spawn_delay, function()
            spawn_pending = false
            send_spawn_request()
        end)
    else
        spawn_pending = false
        send_spawn_request()
    end
end

AddGamePostInit(function()
    log("Initializing: character=" .. auto_spawn_character .. ", delay=" .. auto_spawn_delay .. "s")
    original_ResumeRequestLoadComplete = _G.rawget(_G, "ResumeRequestLoadComplete")
    _G.rawset(_G, "ResumeRequestLoadComplete", hooked_ResumeRequestLoadComplete)
    log("ResumeRequestLoadComplete hooked")
end)

------------------------------------------------------------------------
-- Part 3: Auto god-mode for all players (server-side)
--
-- When a player spawns, make them invincible. This runs on the server
-- (mastersim) so it has authority over health components.
------------------------------------------------------------------------

AddPlayerPostInit(function(player)
    if not _G.TheWorld.ismastersim then return end

    local function apply_godmode()
        if player.components.health then
            player.components.health:SetInvincible(true)
            log("God-mode enabled for " .. tostring(player:GetDisplayName() or player.prefab))
        end
    end

    -- Health component may not be ready at PostInit; retry briefly
    if player.components.health then
        apply_godmode()
    else
        player:DoTaskInTime(0, apply_godmode)
    end
end)

log("Mod loaded")
