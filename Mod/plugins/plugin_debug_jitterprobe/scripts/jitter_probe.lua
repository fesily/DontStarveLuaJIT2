-- jitter_probe.lua — thin Lua face for native authority probe.
--
-- Useful surface (kept):
--   Native Gum ring: Deserialize / SetPos / Teleport / EnablePred
--   Flush: ThePlayer:PushEvent("jitter_probe_flush")
--          -> data/unsafedata/jitter_probe_dump.txt
--
-- Removed (proven non-discriminating for game vs JIT display jitter):
--   wall-clock Transform step/jerk, facing, AnimState, camera, hitch CSV
-- Next investigation needs native render/frame probes, not more Lua wall metrics.

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
print("[JITTER][LUA] probe on (native authority ring only; no wall display metrics)")

local function JLog(tag, fmt, ...)
    print(string.format("[JITTER][LUA][t=%s][%s] " .. fmt,
        tostring(GetTick and GetTick() or -1), tag, ...))
end

-- Sparse sim-tick pos samples: low rate, only large steps printed.
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

        local last_x, last_z
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
            if d >= POS_PRINT_MIN_D then
                JLog("pos", "xyz=%.4f,%.4f,%.4f d=%.5f phase=%s", x, y, z, d, phase)
            end
            last_x, last_z = x, z
        end)

        local last_pred = pred
        inst:DoPeriodicTask(5, function()
            if not inst:IsValid() then
                return
            end
            local p = Profile and Profile:GetMovementPredictionEnabled()
            local loco2 = inst.components.locomotor
            if p ~= last_pred then
                if n_d > 0 then
                    local mean = sum_d / n_d
                    local var = sum_d2 / n_d - mean * mean
                    if var < 0 then var = 0 end
                    JLog("stats", "phase=%s n=%d mean_d=%.5f stdev_d=%.5f max_d=%.5f loco=%s",
                        phase, n_d, mean, math.sqrt(var), max_d, loco2 and "Y" or "N")
                end
                sum_d, sum_d2, n_d, max_d = 0, 0, 0, 0
                phase = p and "on" or "off"
                last_pred = p
                JLog("mode", "pred_profile=%s loco=%s (changed)", tostring(p), loco2 and "Y" or "N")
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

        inst:ListenForEvent("playerdeactivated", function()
            do_flush("deactivated")
        end)
    end)
end)

print("[JITTER][LUA] loaded — native ring only; PushEvent('jitter_probe_flush') to dump")
