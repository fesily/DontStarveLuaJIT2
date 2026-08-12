-- jitter_probe.lua — thin Lua face for native authority + frame/render probe.
--
-- Native Gum ring (Win x64):
--   Authority: Deserialize / SetPos / Teleport / EnablePred
--   Frame:     FrameBegin (dt_s) / FrameEnd (wall_ms, cache_ms, draw_ms)
--   Render:    CacheRender (ActualCacheRender) / DrawCache (DrawCacheRender)
-- Flush: ThePlayer:PushEvent("jitter_probe_flush")
--        -> data/unsafedata/jitter_probe_dump_<vm>_<timestamp>.txt
--        -> data/unsafedata/jitter_probe_dump_latest.txt (alias)
--
-- Hypothesis (pred OFF): pos is server-authoritative (ok), but walk anim
-- should be local-driven. Stock engine still replicates AnimState (hash/bank/
-- time on full-sync / anim switch). Probe samples Lua AnimState + binds
-- native track_self to local Transform.
-- FIX: hook cAnimStateComponent::Deserialize to preserve flAnimTime for local
-- player — anim hash/bank changes still apply, only time stays local.
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

local function set_vm_tag()
    local tag = "run"
    if GameInjector.DS_LUAJIT_get_vm_type_name then
        local ok, name = pcall(GameInjector.DS_LUAJIT_get_vm_type_name, 0)
        if ok and type(name) == "string" and name ~= "" then
            tag = name
        end
    elseif jit and jit.version then
        tag = "jit"
    else
        tag = "game"
    end
    tag = tostring(tag):gsub("[^%w_%-]", "_")
    if GameInjector.DS_LUAJIT_jitter_probe_set_vm_tag then
        GameInjector.DS_LUAJIT_jitter_probe_set_vm_tag(tag)
        print("[JITTER][LUA] vm_tag=" .. tag)
    end
end
set_vm_tag()

print("[JITTER][LUA] probe on (native authority + frame/render; unique dump names)")

local function JLog(tag, fmt, ...)
    print(string.format("[JITTER][LUA][t=%s][%s] " .. fmt,
        tostring(GetTick and GetTick() or -1), tag, ...))
end

-- Sparse sim-tick pos samples: low rate, only large steps printed.
local SAMPLE_EVERY = 10
local POS_PRINT_MIN_D = 0.05
local ANIM_SAMPLE_EVERY = 15 -- ~0.5s at 30Hz sim

local function do_flush(reason)
    set_vm_tag()
    -- Print AnimState hook diagnostics (Lua 5.1 compatible: int returns, no FFI).
    local installed, calls, matches, preserved = 0, 0, 0, 0
    if GameInjector.DS_LUAJIT_jitter_probe_get_anim_hook_status then
        installed = GameInjector.DS_LUAJIT_jitter_probe_get_anim_hook_status() or 0
    end
    if GameInjector.DS_LUAJIT_jitter_probe_get_anim_call_count then
        calls = GameInjector.DS_LUAJIT_jitter_probe_get_anim_call_count() or 0
    end
    if GameInjector.DS_LUAJIT_jitter_probe_get_anim_match_count then
        matches = GameInjector.DS_LUAJIT_jitter_probe_get_anim_match_count() or 0
    end
    if GameInjector.DS_LUAJIT_jitter_probe_get_anim_preserve_count then
        preserved = GameInjector.DS_LUAJIT_jitter_probe_get_anim_preserve_count() or 0
    end
    print(string.format("[JITTER][LUA] anim_hook: installed=%s calls=%s matches=%s preserved=%s",
        tostring(installed), tostring(calls), tostring(matches), tostring(preserved)))
    if GameInjector.DS_LUAJIT_jitter_probe_flush then
        print("[JITTER][LUA] flush requested: " .. tostring(reason))
        GameInjector.DS_LUAJIT_jitter_probe_flush()
    end
end

local function bind_track_self(inst)
    if not GameInjector.DS_LUAJIT_jitter_probe_set_track_entity
        and not GameInjector.DS_LUAJIT_jitter_probe_set_track then
        print("[JITTER][LUA][track] native set_track* missing — rebuild DLL")
        return
    end
    local ent = inst and inst.entity
    if not ent then
        JLog("track", "no inst.entity")
        return
    end
    -- Prefer entity* -> transform* native resolve (Win x64 offsets).
    if GameInjector.DS_LUAJIT_entity_get_raw_ptr
        and GameInjector.DS_LUAJIT_jitter_probe_set_track_entity then
        local ok, raw = pcall(GameInjector.DS_LUAJIT_entity_get_raw_ptr, ent)
        if ok and raw and raw ~= 0 then
            GameInjector.DS_LUAJIT_jitter_probe_set_track_entity(raw)
            -- Also set local player entity for AnimState flAnimTime preservation.
            if GameInjector.DS_LUAJIT_jitter_probe_set_local_player_entity then
                GameInjector.DS_LUAJIT_jitter_probe_set_local_player_entity(raw)
                print(string.format("[JITTER][LUA] local_player_entity=%s (anim time preserve ON)", tostring(raw)))
            end
            print(string.format("[JITTER][LUA] track_entity bound raw=%s", tostring(raw)))
            JLog("track", "bound via entity_get_raw_ptr raw=%s", tostring(raw))
            return
        end
        JLog("track", "entity_get_raw_ptr failed ok=%s raw=%s", tostring(ok), tostring(raw))
    end
end

local function sample_anim(inst)
    local as = inst.AnimState
    if not as then
        return
    end
    local bank, anim, time, facing, len
    local function try(method, ...)
        if type(as[method]) ~= "function" then
            return nil
        end
        local ok, v = pcall(as[method], as, ...)
        if ok then
            return v
        end
        return nil
    end
    bank = try("GetCurrentBankName") or try("GetBank")
    -- DST often lacks GetCurrentAnimationName; probe several.
    anim = try("GetCurrentAnimationName")
        or try("GetCurrentAnimation")
        or try("GetAnimState")
    -- Some builds expose only IsCurrentAnimation; leave anim nil then.
    time = try("GetCurrentAnimationTime")
    len = try("GetCurrentAnimationLength")
    facing = try("GetCurrentFacing") or try("GetFacing")
    return bank, anim, time, facing, len
end

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then
            return
        end
        bind_track_self(inst)
        -- rebind a few times: entity/proxy can rebind after spawn
        for _, delay in ipairs({0.5, 1.5, 3.0}) do
            inst:DoTaskInTime(delay, function(i)
                if ThePlayer == i then
                    bind_track_self(i)
                end
            end)
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
        local last_bank, last_anim, last_time, last_facing
        local anim_reset = 0
        local anim_back = 0
        local anim_n = 0

        inst:DoPeriodicTask(0, function()
            if not inst:IsValid() then
                return
            end
            tick_i = tick_i + 1
            if tick_i % SAMPLE_EVERY == 0 then
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
            end

            if tick_i % ANIM_SAMPLE_EVERY == 0 then
                local bank, anim, time, facing, alen = sample_anim(inst)
                if anim ~= nil or bank ~= nil or type(time) == "number" then
                    anim_n = anim_n + 1
                    local changed = (bank ~= last_bank) or (anim ~= last_anim and anim ~= nil and last_anim ~= nil)
                    -- Loop wrap: time restarts near 0 after progressing. Not authority rewind.
                    local loop_wrap = (type(time) == "number" and type(last_time) == "number"
                        and last_time > 0.2 and time < 0.15
                        and (alen == nil or last_time + 0.05 >= (alen * 0.7)))
                    local tback = (type(time) == "number" and type(last_time) == "number"
                        and time + 0.05 < last_time and not changed and not loop_wrap
                        -- ignore tiny float noise; require meaningful rewind
                        and (last_time - time) > 0.2)
                    if changed then
                        anim_reset = anim_reset + 1
                        JLog("anim", "chg bank=%s anim=%s t=%s len=%s face=%s",
                            tostring(bank), tostring(anim), tostring(time), tostring(alen), tostring(facing))
                    elseif loop_wrap then
                        -- keep quiet unless debugging; still count via sample continuity
                    elseif tback then
                        anim_back = anim_back + 1
                        JLog("anim", "time_back bank=%s anim=%s t=%.4f<-%.4f len=%s face=%s",
                            tostring(bank), tostring(anim), time, last_time, tostring(alen), tostring(facing))
                    end
                    last_bank, last_anim, last_time, last_facing = bank, anim, time, facing
                end
            end
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
            JLog("anim_stats", "n=%d chg=%d time_back=%d last=%s/%s t=%s",
                anim_n, anim_reset, anim_back,
                tostring(last_bank), tostring(last_anim), tostring(last_time))
            do_flush("event")
        end)

        inst:ListenForEvent("playerdeactivated", function()
            do_flush("deactivated")
        end)
    end)
end)

print("[JITTER][LUA] loaded — native ring + local track + anim samples; PushEvent('jitter_probe_flush')")
