-- jitter_probe.lua — client samples for prediction-OFF / high-tick jitter.
--
-- Layers:
--   1) Native ring: Transform Deserialize/SetPos/Teleport
--        ThePlayer:PushEvent("jitter_probe_flush") -> data/unsafedata/jitter_probe_dump.txt
--   2) Wall-clock display (PlayerController:OnWallUpdate ~60Hz):
--        step / jerk of Transform
--        facing (Transform:GetRotation) delta
--        AnimState name + time rewind/jump
--        TheCamera position delta (if present)
--        wall-frame hitch (dt_wall spikes)
--      dump: unsafedata/jitter_display_<phase>_<vm>.txt  (io2 / io)
--
-- Compare game VM vs JIT on same route, EnableClientSmooth off.

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
print("[JITTER][LUA] probe on (authority + wall: pos/anim/facing/cam/hitch)")

local function JLog(tag, fmt, ...)
    print(string.format("[JITTER][LUA][t=%s][%s] " .. fmt,
        tostring(GetTick and GetTick() or -1), tag, ...))
end

local function wall_now()
    if GetTimeRealSeconds ~= nil then
        return GetTimeRealSeconds()
    end
    return GetTime()
end

local function hypot2(dx, dz)
    return math.sqrt(dx * dx + dz * dz)
end

local function hypot3(dx, dy, dz)
    return math.sqrt(dx * dx + dy * dy + dz * dz)
end

local function pred_on()
    return Profile ~= nil
        and Profile.GetMovementPredictionEnabled ~= nil
        and Profile:GetMovementPredictionEnabled()
end

local function vm_tag()
    if GameInjector.DS_LUAJIT_get_vm_type_name then
        local ok, name = pcall(GameInjector.DS_LUAJIT_get_vm_type_name, 0)
        if ok and type(name) == "string" and name ~= "" then
            return name
        end
    end
    if jit and jit.version then
        return "jit"
    end
    return "game"
end

local function do_flush(reason)
    if GameInjector.DS_LUAJIT_jitter_probe_flush then
        print("[JITTER][LUA] flush requested: " .. tostring(reason))
        GameInjector.DS_LUAJIT_jitter_probe_flush()
    end
end

local function percentile(sorted, p)
    if #sorted == 0 then
        return 0
    end
    local i = math.floor(p * (#sorted - 1)) + 1
    if i < 1 then i = 1 end
    if i > #sorted then i = #sorted end
    return sorted[i]
end

local function stats_of(list)
    if #list == 0 then
        return { n = 0, mean = 0, stdev = 0, med = 0, p90 = 0, p99 = 0, max = 0 }
    end
    local sum, sum2, mx = 0, 0, 0
    for i = 1, #list do
        local v = list[i]
        sum = sum + v
        sum2 = sum2 + v * v
        if v > mx then mx = v end
    end
    local mean = sum / #list
    local var = sum2 / #list - mean * mean
    if var < 0 then var = 0 end
    local s = {}
    for i = 1, #list do s[i] = list[i] end
    table.sort(s)
    return {
        n = #list,
        mean = mean,
        stdev = math.sqrt(var),
        med = percentile(s, 0.50),
        p90 = percentile(s, 0.90),
        p99 = percentile(s, 0.99),
        max = mx,
    }
end

local function push_capped(list, v, cap)
    if #list < cap then
        list[#list + 1] = v
    end
end

local function safe_anim(inst)
    local as = inst.AnimState
    if as == nil then
        return nil, nil
    end
    local name, t
    if as.GetCurrentAnimationName then
        local ok, v = pcall(function() return as:GetCurrentAnimationName() end)
        if ok then name = v end
    end
    if as.GetCurrentAnimationTime then
        local ok, v = pcall(function() return as:GetCurrentAnimationTime() end)
        if ok and type(v) == "number" then t = v end
    end
    return name, t
end

local function safe_rot(inst)
    if inst.Transform and inst.Transform.GetRotation then
        local ok, v = pcall(function() return inst.Transform:GetRotation() end)
        if ok and type(v) == "number" then
            return v
        end
    end
    return nil
end

local function safe_cam()
    local cam = rawget(_G, "TheCamera")
    if cam == nil then
        return nil, nil, nil
    end
    -- FollowCamera often has currentpos / GetPos
    if cam.currentpos ~= nil then
        local p = cam.currentpos
        if p and p.x then
            return p.x, p.y, p.z
        end
    end
    if cam.GetPos then
        local ok, x, y, z = pcall(function()
            local a, b, c = cam:GetPos()
            return a, b, c
        end)
        if ok then
            return x, y, z
        end
    end
    if cam.GetTarget and cam.GetTarget() and cam.GetTarget().Transform then
        local ok, x, y, z = pcall(function()
            return cam:GetTarget().Transform:GetWorldPosition()
        end)
        if ok then
            return x, y, z
        end
    end
    return nil, nil, nil
end

local function ang_diff(a, b)
    -- shortest signed degrees difference a-b in (-180, 180]
    local d = (a - b) % 360
    if d > 180 then
        d = d - 360
    elseif d <= -180 then
        d = d + 360
    end
    return d
end

local function write_display_dump(phase, store)
    local iolib = rawget(_G, "io2") or io
    if type(iolib) ~= "table" or type(iolib.open) ~= "function" then
        JLog("display", "dump skip: no io/io2.open")
        return
    end
    local tag = tostring(phase or "na") .. "_" .. tostring(vm_tag() or "na")
    tag = tag:gsub("[^%w_%-]", "_")
    local candidates = {
        "unsafedata/jitter_display_" .. tag .. ".txt",
        "unsafedata/jitter_display.txt",
    }
    local f, path, last_err
    for i = 1, #candidates do
        path = candidates[i]
        local ok, a, b = pcall(iolib.open, path, "w")
        if ok and a then
            f = a
            break
        end
        last_err = (not ok) and tostring(a) or tostring(b or a)
        f = nil
    end
    if not f then
        JLog("display", "dump open failed last=%s err=%s io=%s",
            tostring(path), tostring(last_err), rawget(_G, "io2") and "io2" or "io")
        return
    end
    local n = #store.steps
    local okw, err = pcall(function()
        f:write(string.format(
            "# phase=%s vm=%s n=%d cols=i,dt_ms,step,jerk,drot,anim_dt,anim_chg,cam_step,hitch\n",
            tostring(phase), vm_tag(), n))
        f:write("i,dt_ms,step,jerk,drot,anim_dt,anim_chg,cam_step,hitch\n")
        for i = 1, n do
            f:write(string.format(
                "%d,%.3f,%.6f,%.4f,%.3f,%.5f,%d,%.6f,%d\n",
                i,
                (store.dts[i] or 0) * 1000,
                store.steps[i] or 0,
                store.jerks[i] or 0,
                store.drots[i] or 0,
                store.anim_dts[i] or 0,
                (store.anim_chg[i] and 1) or 0,
                store.cam_steps[i] or 0,
                (store.hitches[i] and 1) or 0))
        end
        f:close()
    end)
    if not okw then
        pcall(function() f:close() end)
        JLog("display", "dump write failed path=%s err=%s", tostring(path), tostring(err))
        return
    end
    JLog("display", "dump wrote %s n=%d", tostring(path), n)
end

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then
            return
        end

        local loco = inst.components and inst.components.locomotor
        local pred = pred_on()
        JLog("mode", "pred_profile=%s loco=%s sg=%s vm=%s",
            tostring(pred),
            loco and "Y" or "N",
            (inst.sg and inst.sg.currentstate and inst.sg.currentstate.name) or (inst.sg and "active") or "nil",
            vm_tag())

        -- ---- sparse sim-tick samples (legacy) ----
        local SAMPLE_EVERY = 10
        local POS_PRINT_MIN_D = 0.05
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
            local d = last_x and hypot2(x - last_x, z - last_z) or 0
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

        -- ---- wall-clock multi-probe store ----
        local MAX_STORE = 3600
        local store = {
            steps = {}, jerks = {}, dts = {},
            drots = {}, anim_dts = {}, anim_chg = {},
            cam_steps = {}, hitches = {},
        }
        local w_last_x, w_last_z, w_last_t
        local w_last_rot
        local w_last_anim, w_last_anim_t
        local w_last_cx, w_last_cy, w_last_cz
        local w_n, w_freeze_n = 0, 0
        local w_anim_chg_n, w_anim_rewind_n = 0, 0
        local w_hitch_n = 0
        local w_sum_drot, w_max_drot = 0, 0
        local w_sum_cam, w_max_cam = 0, 0
        local w_print_every = 5.0
        local w_last_print = wall_now()
        local JERK_PRINT_MIN = 20
        local HITCH_MS = 25 -- wall frame longer than this = hitch (60Hz target ~16.7)
        local ANIM_REWIND_EPS = 0.02 -- anim time went backwards without name change
        local FACING_SPIKE_DEG = 25

        local function reset_wall_stats()
            store = {
                steps = {}, jerks = {}, dts = {},
                drots = {}, anim_dts = {}, anim_chg = {},
                cam_steps = {}, hitches = {},
            }
            w_last_x, w_last_z, w_last_t = nil, nil, nil
            w_last_rot = nil
            w_last_anim, w_last_anim_t = nil, nil
            w_last_cx, w_last_cy, w_last_cz = nil, nil, nil
            w_n, w_freeze_n = 0, 0
            w_anim_chg_n, w_anim_rewind_n = 0, 0
            w_hitch_n = 0
            w_sum_drot, w_max_drot = 0, 0
            w_sum_cam, w_max_cam = 0, 0
        end

        local function print_wall_stats(tag)
            if w_n == 0 then
                JLog("display", "%s phase=%s n=0", tag, phase)
                return
            end
            local ss = stats_of(store.steps)
            local js = stats_of(store.jerks)
            local ds = stats_of(store.dts)
            local rs = stats_of(store.drots)
            local cs = stats_of(store.cam_steps)
            JLog("display",
                "%s phase=%s vm=%s n=%d step med/p90/max=%.4f/%.4f/%.4f jerk med/p90/max=%.2f/%.2f/%.2f dt_ms med/p90=%.2f/%.2f freeze_frac=%.2f hitch_frac=%.3f anim_chg=%d anim_rew=%d drot_p90=%.2f cam_p90=%.4f",
                tag, phase, vm_tag(), w_n,
                ss.med, ss.p90, ss.max,
                js.med, js.p90, js.max,
                ds.med * 1000, ds.p90 * 1000,
                w_n > 0 and (w_freeze_n / w_n) or 0,
                w_n > 0 and (w_hitch_n / w_n) or 0,
                w_anim_chg_n, w_anim_rewind_n,
                rs.p90, cs.p90)
        end

        local function on_wall_sample(dt)
            if not inst:IsValid() then
                return
            end
            local now = wall_now()
            local x, y, z = inst.Transform:GetWorldPosition()
            local rot = safe_rot(inst)
            local aname, atime = safe_anim(inst)
            local cx, cy, cz = safe_cam()

            if w_last_x ~= nil then
                local step = hypot2(x - w_last_x, z - w_last_z)
                local dt_w = now - w_last_t
                if dt_w < 1e-4 then
                    dt_w = (type(dt) == "number" and dt > 1e-4) and dt or 1e-4
                end
                local jerk = step / dt_w
                local hitch = dt_w * 1000 >= HITCH_MS

                local drot = 0
                if rot ~= nil and w_last_rot ~= nil then
                    drot = math.abs(ang_diff(rot, w_last_rot))
                end

                local anim_dt = 0
                local anim_changed = false
                if aname ~= nil and w_last_anim ~= nil then
                    if aname ~= w_last_anim then
                        anim_changed = true
                        w_anim_chg_n = w_anim_chg_n + 1
                    elseif atime ~= nil and w_last_anim_t ~= nil then
                        anim_dt = atime - w_last_anim_t
                        if anim_dt < -ANIM_REWIND_EPS then
                            w_anim_rewind_n = w_anim_rewind_n + 1
                            JLog("anim", "rewind name=%s dt=%.4f->%.4f phase=%s",
                                tostring(aname), w_last_anim_t, atime, phase)
                        end
                    end
                elseif aname ~= nil and w_last_anim == nil then
                    -- first sample with anim
                end

                local cam_step = 0
                if cx ~= nil and w_last_cx ~= nil then
                    cam_step = hypot3(cx - w_last_cx, (cy or 0) - (w_last_cy or 0), (cz or 0) - (w_last_cz or 0))
                end

                w_n = w_n + 1
                if step < 1e-4 then
                    w_freeze_n = w_freeze_n + 1
                end
                if hitch then
                    w_hitch_n = w_hitch_n + 1
                end
                w_sum_drot = w_sum_drot + drot
                if drot > w_max_drot then w_max_drot = drot end
                w_sum_cam = w_sum_cam + cam_step
                if cam_step > w_max_cam then w_max_cam = cam_step end

                push_capped(store.steps, step, MAX_STORE)
                push_capped(store.jerks, jerk, MAX_STORE)
                push_capped(store.dts, dt_w, MAX_STORE)
                push_capped(store.drots, drot, MAX_STORE)
                push_capped(store.anim_dts, anim_dt, MAX_STORE)
                push_capped(store.anim_chg, anim_changed, MAX_STORE)
                push_capped(store.cam_steps, cam_step, MAX_STORE)
                push_capped(store.hitches, hitch, MAX_STORE)

                if jerk >= JERK_PRINT_MIN and step >= 0.05 then
                    JLog("jerk", "step=%.4f jerk=%.1f dt_ms=%.2f phase=%s xyz=%.3f,%.3f",
                        step, jerk, dt_w * 1000, phase, x, z)
                end
                if drot >= FACING_SPIKE_DEG then
                    JLog("facing", "drot=%.1f phase=%s rot=%.1f", drot, phase, rot or -1)
                end
                if hitch then
                    JLog("hitch", "dt_ms=%.2f step=%.4f phase=%s", dt_w * 1000, step, phase)
                end
                if anim_changed then
                    JLog("anim", "chg %s -> %s phase=%s",
                        tostring(w_last_anim), tostring(aname), phase)
                end
            end

            w_last_x, w_last_z, w_last_t = x, z, now
            w_last_rot = rot
            w_last_anim, w_last_anim_t = aname, atime
            w_last_cx, w_last_cy, w_last_cz = cx, cy, cz

            if now - w_last_print >= w_print_every then
                w_last_print = now
                print_wall_stats("periodic")
            end
        end

        local pc = inst.components and inst.components.playercontroller
        if pc ~= nil then
            local old_wall = pc.OnWallUpdate
            function pc:OnWallUpdate(dt, ...)
                if old_wall ~= nil then
                    old_wall(self, dt, ...)
                end
                if self.inst == inst then
                    on_wall_sample(dt)
                end
            end
            JLog("display", "hooked PlayerController:OnWallUpdate (pos/anim/facing/cam/hitch)")
        else
            local driver = {
                OnWallUpdate = function(_, dt)
                    on_wall_sample(dt)
                end,
            }
            if inst.StartWallUpdatingComponent then
                inst.components._jitter_display_driver = driver
                inst:StartWallUpdatingComponent(driver)
                JLog("display", "StartWallUpdatingComponent driver installed")
            else
                inst:DoPeriodicTask(0, function()
                    on_wall_sample(0)
                end)
                JLog("display", "fallback DoPeriodicTask(0)")
            end
        end

        local last_pred = pred
        inst:DoPeriodicTask(5, function()
            if not inst:IsValid() then
                return
            end
            local p = pred_on()
            local loco2 = inst.components.locomotor
            if p ~= last_pred then
                if n_d > 0 then
                    local mean = sum_d / n_d
                    local var = sum_d2 / n_d - mean * mean
                    if var < 0 then var = 0 end
                    JLog("stats", "phase=%s n=%d mean_d=%.5f stdev_d=%.5f max_d=%.5f loco=%s",
                        phase, n_d, mean, math.sqrt(var), max_d, loco2 and "Y" or "N")
                end
                print_wall_stats("phase_end")
                write_display_dump(phase, store)
                sum_d, sum_d2, n_d, max_d = 0, 0, 0, 0
                reset_wall_stats()
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
            print_wall_stats("flush")
            write_display_dump(phase, store)
            do_flush("event")
        end)

        inst:ListenForEvent("playerdeactivated", function()
            print_wall_stats("deactivated")
            write_display_dump(phase, store)
            do_flush("deactivated")
        end)
    end)
end)

print("[JITTER][LUA] loaded — multi-probe wall metrics; PushEvent('jitter_probe_flush') for dumps")
