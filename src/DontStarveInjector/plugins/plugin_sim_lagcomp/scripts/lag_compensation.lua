-- lag_compensation.lua
-- Monkey-patches TheSim:FindEntities to extrapolate remote player positions
-- by half-RTT before the spatial query, then restores them afterward.
-- Only active on the master sim (server context).

assert(TheWorld.ismastersim)
local ffi = require("ffi")
local load_library_ex = require("luavm.ffi_load")
local GameInjector = _G.rawget(_G, "GameInjector")
if not GameInjector then return end

local lib = load_library_ex("plugin_sim_lagcomp")
if not lib then
    -- Backward-compatible fallback if plugin DLL not staged
    lib = load_library_ex("Injector")
end
if not lib then return end

ffi.cdef[[
void DS_LUAJIT_lag_comp_init(int max_slots);
void DS_LUAJIT_lag_comp_update_snapshot(void* entity_ptr, int slot, float half_rtt_s);
void DS_LUAJIT_lag_comp_apply_all(void);
void DS_LUAJIT_lag_comp_restore_all(void);
void DS_LUAJIT_lag_comp_clear_slot(int slot);
]]

local MAX_SLOTS
local player_slots = {}
local free_slots = {}

local RTT_REFRESH_INTERVAL = 2

-- Prefer the native per-client RTT (network.stats: DS_LUAJIT_net_client_ping)
-- over the Lua-side ping field; fall back to client.ping when unavailable.
local native_client_ping = GameInjector.DS_LUAJIT_net_client_ping
local warned_native_ping_missing = false

local function row_rtt_ms(client)
    if native_client_ping and type(client.userid) == "string" then
        local ok, ms = pcall(native_client_ping, client.userid)
        if ok and type(ms) == "number" and ms >= 0 then
            return ms, "native"
        end
    end
    return client.ping, "lua"
end

local cached_rtt_map = {}

local function alloc_slot()
    local n = #free_slots
    if n == 0 then return nil end
    local slot = free_slots[n]
    free_slots[n] = nil
    return slot
end

local function free_slot(slot)
    lib.DS_LUAJIT_lag_comp_clear_slot(slot)
    free_slots[#free_slots + 1] = slot
end

local function on_player_joined(world, player)
    local userid = player.userid
    if not userid or userid == "" then return end
    if player_slots[userid] then return end

    local slot = alloc_slot()
    if not slot then return end
    player_slots[userid] = { slot = slot }
end

local function on_player_left(world, player)
    local userid = player.userid
    if not userid then return end
    local entry = player_slots[userid]
    if not entry then return end
    free_slot(entry.slot)
    player_slots[userid] = nil
end

local function is_host_entry(client)
    return client.performance ~= nil
end

local function refresh_rtt_map()
    local map = {}
    local ok, clients = pcall(function() return TheNet:GetClientTable() end)
    if not ok or not clients then
        cached_rtt_map = map
        return
    end
    local saw_client = false
    local saw_native = false
    for _, client in ipairs(clients) do
        if not is_host_entry(client) and client.userid then
            saw_client = true
            local rtt_ms, source = row_rtt_ms(client)
            if type(rtt_ms) == "number" then
                map[client.userid] = rtt_ms / 2000.0
                saw_native = saw_native or source == "native"
            end
        end
    end
    if saw_client and not saw_native and not warned_native_ping_missing then
        warned_native_ping_missing = true
        print("[sim.lagcomp] native client ping unavailable, falling back to GetClientTable().ping")
    end
    cached_rtt_map = map
end

local function update_all_snapshots()
    local players = AllPlayers
    if not players then return end

    for _, player in ipairs(players) do
        local userid = player.userid
        local entry = userid and player_slots[userid]
        if entry then
            local half_rtt = cached_rtt_map[userid] or 0
            local ent_ud = player.entity
            if ent_ud then
                local raw_ptr = GameInjector.DS_LUAJIT_entity_get_raw_ptr(ent_ud)
                if raw_ptr then
                    lib.DS_LUAJIT_lag_comp_update_snapshot(raw_ptr, entry.slot, half_rtt)
                end
            end
        end
    end
end

local sim_mt = getmetatable(TheSim).__index
local original_FindEntities = sim_mt.FindEntities

sim_mt.FindEntities = function(...)
    lib.DS_LUAJIT_lag_comp_apply_all()
    local results = { original_FindEntities(...) }
    lib.DS_LUAJIT_lag_comp_restore_all()
    return unpack(results)
end

AddSimPostInit(function()
    MAX_SLOTS = TheNet:GetServerMaxPlayers() or 6
    lib.DS_LUAJIT_lag_comp_init(MAX_SLOTS)

    for i = MAX_SLOTS - 1, 0, -1 do
        free_slots[#free_slots + 1] = i
    end

    for _, player in ipairs(AllPlayers) do
        on_player_joined(TheWorld, player)
    end

    TheWorld:ListenForEvent("ms_playerjoined", on_player_joined)
    TheWorld:ListenForEvent("ms_playerleft", on_player_left)

    refresh_rtt_map()

    scheduler:ExecutePeriodic(RTT_REFRESH_INTERVAL, function()
        refresh_rtt_map()
    end, nil, nil, "lag_comp_rtt_refresh")

    StaticScheduler:ExecutePeriodic(FRAMES, function()
        update_all_snapshots()
    end, nil, nil, "lag_comp_snapshot_tick")
end)
