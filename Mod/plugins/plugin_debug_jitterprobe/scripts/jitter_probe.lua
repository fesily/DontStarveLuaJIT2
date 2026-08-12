-- jitter_probe.lua — zero-hitch client samples (prediction-OFF investigation).
-- Engine ring: NO auto flush (flush dumps thousands of lines → hitch).
-- Flush only: console ThePlayer:PushEvent("jitter_probe_flush") or unload.

if TheNet and TheNet:IsDedicated() then
    return
end

local GameInjector = _G.rawget(_G, "GameInjector")
if not GameInjector then
    print("[JITTER][LUA] GameInjector missing — probe inactive")
    return
end

local enable_fn = GameInjector.DS_LUAJIT_jitter_probe_enable
if type(enable_fn) ~= "function" then
    print("[JITTER][LUA] DS_LUAJIT_jitter_probe_enable missing — rebuild/replace native DLL")
    return
end

enable_fn(true)
if GameInjector.DS_LUAJIT_jitter_probe_set_local_only then
    GameInjector.DS_LUAJIT_jitter_probe_set_local_only(true)
end
print("[JITTER][LUA] probe on (no auto-flush; sparse pos only)")

local function JLog(tag, fmt, ...)
    print(string.format("[JITTER][LUA][t=%s][%s] " .. fmt,
        tostring(GetTick and GetTick() or -1), tag, ...))
end

-- 10 ticks ≈ 0.33s @30Hz — enough for stair-step stats, low print rate.
local SAMPLE_EVERY = 10
local POS_PRINT_MIN_D = 0.05

local function do_flush(reason)
    if GameInjector.DS_LUAJIT_jitter_probe_flush then
        print("[JITTER][LUA] flush requested: " .. tostring(reason))
        GameInjector.DS_LUAJIT_jitter_probe_flush()
    end
end

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then
            return
        end
        local loco = inst.components and inst.components.locomotor
        local pred = Profile and Profile.GetMovementPredictionEnabled and Profile:GetMovementPredictionEnabled()
        JLog("mode", "pred_profile=%s loco=%s sg=%s",
            tostring(pred),
            loco and "Y" or "N",
            (inst.sg and inst.sg.currentstate and inst.sg.currentstate.name) or (inst.sg and "active") or "nil")

        local last_x, last_z, last_t
        local tick_i = 0
        local sum_d, sum_d2, n_d, max_d = 0, 0, 0, 0
        local phase = pred and "on" or "off"

        inst:DoPeriodicTask(0, function()
            if not inst:IsValid() then
                return
            end
            tick_i = tick_i + 1
            if tick_i % SAMPLE_EVERY ~= 0 then
                return
            end
            local x, y, z = inst.Transform:GetWorldPosition()
            local d = last_x and math.sqrt((x - last_x) * (x - last_x) + (z - last_z) * (z - last_z)) or 0
            if last_x then
                sum_d = sum_d + d
                sum_d2 = sum_d2 + d * d
                n_d = n_d + 1
                if d > max_d then max_d = d end
            end
            -- Rare print: only large steps (stair evidence). Stats accumulate silently.
            if d >= POS_PRINT_MIN_D then
                JLog("pos", "xyz=%.4f,%.4f,%.4f d=%.5f phase=%s", x, y, z, d, phase)
            end
            last_x, last_z = x, z
        end)

        -- Mode poll every 5s (not 2s); print only on change.
        local last_pred = pred
        inst:DoPeriodicTask(5, function()
            if not inst:IsValid() then
                return
            end
            local p = Profile and Profile:GetMovementPredictionEnabled()
            local loco = inst.components.locomotor
            if p ~= last_pred then
                -- Phase change: print silent stats for previous phase, then switch.
                if n_d > 0 then
                    local mean = sum_d / n_d
                    local var = sum_d2 / n_d - mean * mean
                    if var < 0 then var = 0 end
                    JLog("stats", "phase=%s n=%d mean_d=%.5f stdev_d=%.5f max_d=%.5f loco=%s",
                        phase, n_d, mean, math.sqrt(var), max_d, loco and "Y" or "N")
                end
                sum_d, sum_d2, n_d, max_d = 0, 0, 0, 0
                phase = p and "on" or "off"
                last_pred = p
                JLog("mode", "pred_profile=%s loco=%s (changed)", tostring(p), loco and "Y" or "N")
            end
        end)

        inst:ListenForEvent("jitter_probe_flush", function()
            if n_d > 0 then
                local mean = sum_d / n_d
                local var = sum_d2 / n_d - mean * mean
                if var < 0 then var = 0 end
                JLog("stats", "phase=%s n=%d mean_d=%.5f stdev_d=%.5f max_d=%.5f",
                    phase, n_d, mean, math.sqrt(var), max_d)
            end
            do_flush("event")
        end)

        -- End-of-session: one flush when player removed (leave world).
        inst:ListenForEvent("playerdeactivated", function()
            do_flush("deactivated")
        end)
    end)
end)

-- Manual: c_announce / console: ThePlayer:PushEvent("jitter_probe_flush")
print("[JITTER][LUA] loaded — NO periodic flush; PushEvent('jitter_probe_flush') to dump ring once")
