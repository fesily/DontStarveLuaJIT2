---@diagnostic disable: lowercase-global, undefined-global
_G = GLOBAL

local LOG_PREFIX = "[StressBot]"

local function log(...)
    print(LOG_PREFIX, ...)
end

local auto_spawn_character = _G.os.getenv("STRESS_CHARACTER") or GetModConfigData("auto_spawn_character") or "wilson"
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
local LAN_SEARCH_OFFLINE = _G.os.getenv("STRESS_LAN_OFFLINE") == "1"
local DIRECT_CONNECT_IP = _G.os.getenv("STRESS_CONNECT_IP")
local DIRECT_CONNECT_PORT = _G.tonumber(_G.os.getenv("STRESS_CONNECT_PORT")) or 10999

local function try_auto_connect(screen_inst)
    if auto_connect_done then return end
    auto_connect_done = true

    if LAN_SEARCH_OFFLINE then
        -- MainScreen defaults to online mode. Follow its offline-login path
        -- before searching, rather than relying on the launch flag alone.
        _G.TheNet:NotifyAuthenticationFailure()
        _G.TheFrontEnd:SetOfflineMode(true)
    end
    if _G.os.getenv("STRESS_SKIP_MOD_WARNING") == "1" and _G.Profile then
        -- Fresh benchmark profiles must not wait for the server-mod warning.
        _G.Profile.ShouldWarnModsEnabled = function() return false end
    end

    -- The inject smoke owns a local dedicated server; connect to its known
    -- endpoint instead of depending on broadcast discovery and listing filters.
    if DIRECT_CONNECT_IP then
        log("Connecting directly to " .. DIRECT_CONNECT_IP .. ":" .. tostring(DIRECT_CONNECT_PORT))
        if not _G.c_connect(DIRECT_CONNECT_IP, DIRECT_CONNECT_PORT) then
            log("ERROR: direct connection failed to start")
        end
        return
    end

    -- Match ServerListingScreen: the argument selects offline LAN listings.
    log("Starting LAN server search for auto-connect... offline=" .. tostring(LAN_SEARCH_OFFLINE)
        .. ", network_online=" .. tostring(_G.TheNet:IsOnlineMode()))
    _G.TheNet:SearchLANServers(LAN_SEARCH_OFFLINE)

    local elapsed = 0
    local function poll()
        elapsed = elapsed + LAN_SEARCH_INTERVAL

        if _G.TheNet:GetServerListingReadDirty() then
            local listings = _G.TheNet:GetServerListings()
            log("LAN listings updated: " .. tostring(listings and #listings or 0))
            if listings and #listings > 0 then
                local server = listings[1]
                log("Found LAN server: " .. tostring(server.name)
                    .. " (guid=" .. tostring(server.guid)
                    .. ", offline=" .. tostring(server.offline) .. ")")
                _G.JoinServer(server)
                return
            end
        end

        if elapsed >= LAN_SEARCH_TIMEOUT then
            log("ERROR: LAN server search timed out after " .. LAN_SEARCH_TIMEOUT .. "s"
                .. ", offline=" .. tostring(LAN_SEARCH_OFFLINE))
            auto_connect_done = false  -- allow retry
            return
        end

        screen_inst.inst:DoTaskInTime(LAN_SEARCH_INTERVAL, poll)
    end

    screen_inst.inst:DoTaskInTime(LAN_SEARCH_INTERVAL, poll)
end

AddClassPostConstruct("screens/redux/mainscreen", function(self)
    if LAN_SEARCH_OFFLINE then
        -- A saved AutoLogin preference otherwise starts an online login at
        -- the same time as our search and resets the offline network state.
        self.auto_login_started = true
        if self.inst._AutoLoginTask ~= nil then
            self.inst._AutoLoginTask:Cancel()
            self.inst._AutoLoginTask = nil
        end
    end
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
