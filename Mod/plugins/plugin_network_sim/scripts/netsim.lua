-- netsim.lua
-- Lua bridge for the native C++ network simulator (client-side only).
-- Bridge functions accessible via GameInjector sol2 table — no ffi/cdef needed.

local GameInjector = rawget(_G, "GameInjector")
if not GameInjector then return end
if GameInjector.DS_LUAJIT_net_sim_enable == nil then return end

local ffi_get_stats

local jit_runtime = rawget(_G, "jit")
if jit_runtime ~= nil then
    local ok_ffi, ffi = pcall(require, "ffi")
    local ok_loader, load_library_ex = pcall(require, "luavm.ffi_load")
    if ok_ffi and ok_loader then
        local ok_lib, lib = pcall(load_library_ex, "Injector")
        if ok_lib and lib ~= nil then
            ffi.cdef[[
                typedef struct {
                    bool enabled;
                    uint32_t delay_ms;
                    uint32_t jitter_ms;
                    uint32_t loss_pct;
                    uint64_t packets_total;
                    uint64_t packets_delayed;
                    uint64_t packets_dropped;
                    uint64_t packets_released;
                    uint32_t queue_depth;
                } NetSimStats;

                const NetSimStats* DS_LUAJIT_net_sim_get_stats(void);
            ]]

            ffi_get_stats = function()
                return lib.DS_LUAJIT_net_sim_get_stats()
            end
        end
    end
end

local NetSim = {}

function NetSim.Enable(on)
    GameInjector.DS_LUAJIT_net_sim_enable(on)
end

function NetSim.Set(delay_ms, jitter_ms, loss_pct)
    GameInjector.DS_LUAJIT_net_sim_set(delay_ms, jitter_ms, loss_pct)
end

function NetSim.Update()
    GameInjector.DS_LUAJIT_net_sim_update()
end

function NetSim.GetStats()
    if ffi_get_stats ~= nil then
        return ffi_get_stats()
    end
    return GameInjector.DS_LUAJIT_net_sim_get_stats()
end

function NetSim.Simulate(delay_ms, jitter_ms, loss_pct)
    NetSim.Set(delay_ms, jitter_ms, loss_pct)
    NetSim.Enable(true)
end

function NetSim.Stop()
    NetSim.Enable(false)
end

rawset(_G, "NetSim", NetSim)

AddSimPostInit(function()
    if not TheWorld or TheWorld.ismastersim then return end
    scheduler:ExecutePeriodic(0, function()
        GameInjector.DS_LUAJIT_net_sim_update()
    end)
end)

-- HUD overlay: shows live NetSim stats on the player HUD (client only)
local Text = require "widgets/text"
AddClassPostConstruct("screens/playerhud", function(self)
    local text = self.over_root:AddChild(Text(BODYTEXTFONT, 18))
    text:SetColour(1, 0.843, 0, 0.8)  -- #FFD700 at 80% opacity
    text:SetPosition(0, -300)
    text:Hide()
    self.net_sim_display = text

    self.inst:DoPeriodicTask(0.5, function()
        local stats = NetSim.GetStats()
        if not stats then
            text:Hide()
            return
        end
        local stats_ref = ffi_get_stats ~= nil and stats[0] or stats
        if stats_ref.enabled then
            text:SetString(string.format(
                "NetSim: delay=%dms jitter=%dms loss=%d%% | queued=%d sent=%d dropped=%d",
                tonumber(stats_ref.delay_ms) or 0,
                tonumber(stats_ref.jitter_ms) or 0,
                math.floor((tonumber(stats_ref.loss_pct) or 0) + 0.5),
                tonumber(stats_ref.queue_depth) or 0,
                tonumber(stats_ref.packets_released) or 0,
                tonumber(stats_ref.packets_dropped) or 0
            ))
            text:Show()
        else
            text:Hide()
        end
    end)
end)
