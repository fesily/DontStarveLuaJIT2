-- jitter_probe.lua — native authority probe + pred-OFF local anim drive.
--
-- pred OFF stock path: ClearStateGraph + no locomotor → anim is 100% network.
-- Network AnimTime rewinds look like jitter; time-preserve alone was ineffective.
--
-- Approach:
--   1) While walking (pred OFF): native forces Deserialize local_a0 for local player
--      (skip PlayMode/AnimHash/AnimTime) AND Lua plays run/idle from input.
--   2) While not walking: release ownership → network drives action/idle anims.
--   3) Position stays server-authoritative (no EnableMovementPrediction).
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
    if APP_VERSION then
        tag = tostring(APP_VERSION)
    end
    if TheSim and TheSim.GetLuaVersion then
        local ok, v = pcall(TheSim.GetLuaVersion, TheSim)
        if ok and v then
            tag = (string.find(tostring(v), "JIT", 1, true) and "jit") or "game"
        end
    end
    if GameInjector.DS_LUAJIT_jitter_probe_set_vm_tag then
        GameInjector.DS_LUAJIT_jitter_probe_set_vm_tag(tag)
    end
end
set_vm_tag()

print("[JITTER][LUA] probe on (pred-OFF local anim own + native local_a0 gate)")

local function JLog(tag, fmt, ...)
    print(string.format("[JITTER][LUA][t=%s][%s] " .. fmt,
        tostring(GetTick and GetTick() or -1), tag, ...))
end

local SAMPLE_EVERY = 10
local POS_PRINT_MIN_D = 0.05
local ANIM_SAMPLE_EVERY = 15

local function set_anim_own(on)
    if GameInjector.DS_LUAJIT_jitter_probe_set_local_anim_own then
        GameInjector.DS_LUAJIT_jitter_probe_set_local_anim_own(on and true or false)
    end
end

-- Camera-relative move dir (mirrors playercontroller GetWorldControllerVector).
local function get_move_dir()
    if not TheInput or not TheCamera then
        return nil
    end
    local xdir = TheInput:GetAnalogControlValue(CONTROL_MOVE_RIGHT)
        - TheInput:GetAnalogControlValue(CONTROL_MOVE_LEFT)
    local ydir = TheInput:GetAnalogControlValue(CONTROL_MOVE_UP)
        - TheInput:GetAnalogControlValue(CONTROL_MOVE_DOWN)
    local deadzone = (TUNING and TUNING.CONTROLLER_DEADZONE_RADIUS) or 0.25
    if math.abs(xdir) < deadzone and math.abs(ydir) < deadzone then
        return nil
    end
    local dir = TheCamera:GetRightVec() * xdir - TheCamera:GetDownVec() * ydir
    if dir.LengthSq and dir:LengthSq() < 1e-6 then
        return nil
    end
    return dir:GetNormalized()
end

local function is_busy_for_anim(inst)
    return inst:HasTag("busy")
        or inst:HasTag("attack")
        or inst:HasTag("nopredict")
        or inst:HasTag("pausepredict")
        or inst:HasTag("sleeping")
        or inst:HasTag("isdead")
end

local function pick_locomote_anims(inst)
    if inst:HasTag("playerghost") then
        return "idle", "idle"
    end
    local inv = inst.replica and inst.replica.inventory
    if inv and inv.IsHeavyLifting and inv:IsHeavyLifting() then
        return "heavy_walk_pre", "heavy_walk"
    end
    if inst:HasTag("wereplayer") then
        return "idle_walk_pre", "idle_walk"
    end
    return "run_pre", "run_loop"
end

local function drive_local_locomote(inst, moving, dir)
    local as = inst.AnimState
    if not as then
        return
    end
    local pre, loop = pick_locomote_anims(inst)
    if moving and dir then
        local rot = -math.atan2(dir.z, dir.x) / DEGREES
        if inst.Transform and inst.Transform.SetRotation then
            inst.Transform:SetRotation(rot)
        end
        if as.IsCurrentAnimation then
            if not (as:IsCurrentAnimation(loop) or as:IsCurrentAnimation(pre)) then
                if as.PlayAnimation then
                    as:PlayAnimation(pre)
                    if as.PushAnimation then
                        as:PushAnimation(loop, true)
                    end
                end
            elseif as:IsCurrentAnimation(pre) and as.AnimDone and as:AnimDone() then
                as:PlayAnimation(loop, true)
            end
        else
            -- Fallback: force loop each tick (less ideal).
            if as.PlayAnimation then
                as:PlayAnimation(loop, true)
            end
        end
    else
        -- Idle while we still own: keep a stable loop so network can't freeze mid-run.
        if as.IsCurrentAnimation and as.PlayAnimation then
            if not as:IsCurrentAnimation("idle_loop")
                and not as:IsCurrentAnimation("heavy_idle")
                and not as:IsCurrentAnimation("idle") then
                local idle = (inst.replica and inst.replica.inventory
                    and inst.replica.inventory.IsHeavyLifting
                    and inst.replica.inventory:IsHeavyLifting()) and "heavy_idle" or "idle_loop"
                as:PlayAnimation(idle, true)
            end
        end
    end
end

local function do_flush(reason)
    set_vm_tag()
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
    local a0_patched, a0_enter, a0_match, own = 0, 0, 0, 0
    if GameInjector.DS_LUAJIT_jitter_probe_get_local_a0_patched then
        a0_patched = GameInjector.DS_LUAJIT_jitter_probe_get_local_a0_patched() or 0
    end
    if GameInjector.DS_LUAJIT_jitter_probe_get_a0_enter_count then
        a0_enter = GameInjector.DS_LUAJIT_jitter_probe_get_a0_enter_count() or 0
    end
    if GameInjector.DS_LUAJIT_jitter_probe_get_a0_match_count then
        a0_match = GameInjector.DS_LUAJIT_jitter_probe_get_a0_match_count() or 0
    end
    if GameInjector.DS_LUAJIT_jitter_probe_get_local_anim_own then
        own = GameInjector.DS_LUAJIT_jitter_probe_get_local_anim_own() or 0
    end
    print(string.format(
        "[JITTER][LUA] anim_hook: installed=%s calls=%s matches=%s preserved=%s | local_a0_patched=%s enter=%s match=%s own=%s",
        tostring(installed), tostring(calls), tostring(matches), tostring(preserved),
        tostring(a0_patched), tostring(a0_enter), tostring(a0_match), tostring(own)))
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
    if GameInjector.DS_LUAJIT_entity_get_raw_ptr
        and GameInjector.DS_LUAJIT_jitter_probe_set_track_entity then
        local ok, raw = pcall(GameInjector.DS_LUAJIT_entity_get_raw_ptr, ent)
        if ok and raw and raw ~= 0 then
            GameInjector.DS_LUAJIT_jitter_probe_set_track_entity(raw)
            if GameInjector.DS_LUAJIT_jitter_probe_set_local_player_entity then
                GameInjector.DS_LUAJIT_jitter_probe_set_local_player_entity(raw)
                print(string.format("[JITTER][LUA] local_player_entity=%s (local_a0 gate target)", tostring(raw)))
            end
            print(string.format("[JITTER][LUA] track_entity bound raw=%s", tostring(raw)))
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
    local bank = try("GetCurrentBankName") or try("GetBank")
    local anim = try("GetCurrentAnimationName") or try("GetCurrentAnimation")
    local time = try("GetCurrentAnimationTime")
    local len = try("GetCurrentAnimationLength")
    local facing = try("GetCurrentFacing") or try("GetFacing")
    return bank, anim, time, facing, len
end

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then
            return
        end
        bind_track_self(inst)
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
        local last_bank, last_anim, last_time
        local anim_reset, anim_back, anim_n = 0, 0, 0
        local own_ticks, own_on_last = 0, false

        -- Every sim tick: pred-OFF locomotion ownership + local PlayAnimation.
        inst:DoPeriodicTask(0, function()
            if not inst:IsValid() or ThePlayer ~= inst then
                set_anim_own(false)
                return
            end
            tick_i = tick_i + 1

            local pred_now = Profile and Profile.GetMovementPredictionEnabled
                and Profile:GetMovementPredictionEnabled()
            local pc = inst.components and inst.components.playercontroller
            local has_loco = inst.components and inst.components.locomotor ~= nil
            local dir = get_move_dir()
            local moving = dir ~= nil
            -- Also honor controller flags when present.
            if pc then
                if pc.directwalking or pc.dragwalking then
                    moving = true
                end
            end
            local busy = is_busy_for_anim(inst)
            local want_own = (not pred_now) and (not has_loco) and (not busy) and moving

            if want_own ~= own_on_last then
                JLog("anim_own", "own=%s moving=%s busy=%s pred=%s",
                    tostring(want_own), tostring(moving), tostring(busy), tostring(pred_now))
                own_on_last = want_own
            end
            set_anim_own(want_own)
            if want_own then
                own_ticks = own_ticks + 1
                drive_local_locomote(inst, true, dir)
            end

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
                    JLog("pos", "xyz=%.4f,%.4f,%.4f d=%.5f phase=%s own=%s",
                        x, y, z, d, phase, tostring(want_own))
                end
                last_x, last_z = x, z
            end

            if tick_i % ANIM_SAMPLE_EVERY == 0 then
                local bank, anim, time, facing, alen = sample_anim(inst)
                if anim ~= nil or bank ~= nil or type(time) == "number" then
                    anim_n = anim_n + 1
                    local changed = (bank ~= last_bank) or (anim ~= last_anim and anim ~= nil and last_anim ~= nil)
                    local loop_wrap = (type(time) == "number" and type(last_time) == "number"
                        and last_time > 0.2 and time < 0.15
                        and (alen == nil or last_time + 0.05 >= (alen * 0.7)))
                    local tback = (type(time) == "number" and type(last_time) == "number"
                        and time + 0.05 < last_time and not changed and not loop_wrap
                        and (last_time - time) > 0.2)
                    if changed then
                        anim_reset = anim_reset + 1
                        JLog("anim", "chg bank=%s anim=%s t=%s face=%s own=%s",
                            tostring(bank), tostring(anim), tostring(time), tostring(facing), tostring(want_own))
                    elseif tback then
                        anim_back = anim_back + 1
                        JLog("anim", "time_back bank=%s anim=%s t=%.4f<-%.4f own=%s",
                            tostring(bank), tostring(anim), time, last_time, tostring(want_own))
                    end
                    last_bank, last_anim, last_time = bank, anim, time
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
            JLog("anim_stats", "n=%d chg=%d time_back=%d own_ticks=%d last=%s/%s t=%s",
                anim_n, anim_reset, anim_back, own_ticks,
                tostring(last_bank), tostring(last_anim), tostring(last_time))
            do_flush("event")
        end)

        inst:ListenForEvent("playerdeactivated", function()
            set_anim_own(false)
            do_flush("deactivated")
        end)
    end)
end)

print("[JITTER][LUA] loaded — pred-OFF local run/idle + gated local_a0; PushEvent('jitter_probe_flush')")
