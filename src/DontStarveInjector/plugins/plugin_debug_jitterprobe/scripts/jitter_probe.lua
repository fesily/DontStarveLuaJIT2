-- jitter_probe.lua — client samples for prediction-OFF / high-tick jitter.
--
-- Native ring (Transform Deserialize/SetPos/Teleport): flush only via
--   ThePlayer:PushEvent("jitter_probe_flush")
-- That ring measures AUTHORITY apply, not "how it looks".
--
-- This Lua face adds WALL-CLOCK display sampling (PlayerController:OnWallUpdate):
--   jerk = |Δpos| / dt_wall  (units/s of the visible Transform)
--   step  = |Δpos| between wall frames
-- High server net tick densifies hard snaps; visual jerk should rise even when
-- residual stays small. Compare game VM vs JIT on the same route with smooth OFF.
--
-- Files:
--   native dump: data/unsafedata/jitter_probe_dump.txt  (C fopen)
--   display dump: unsafedata/jitter_display_<phase>_<vm>.txt  (Lua io/io2)

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
print("[JITTER][LUA] probe on (authority ring + wall display metrics; no auto-flush)")

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

-- Rolling percentile (sorted copy; n is small, wall ~60Hz * few seconds between prints).
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

local function write_display_csv(phase, steps, jerks, dts)
    -- DST sandboxed `io` only allows certain paths under unsafedata/.
    -- Prefer unrestricted io2 (Injector); fall back to game io.
    -- Use .txt (same family as profiler.txt / luajit_config.json); .csv is rejected.
    local iolib = rawget(_G, "io2") or io
    if type(iolib) ~= "table" or type(iolib.open) ~= "function" then
        JLog("display", "csv skip: no io/io2.open")
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
        -- pcall caught error, or open returned nil,err
        last_err = (not ok) and tostring(a) or tostring(b or a)
        f = nil
    end
    if not f then
        JLog("display", "csv open failed last=%s err=%s io=%s",
            tostring(path), tostring(last_err), rawget(_G, "io2") and "io2" or "io")
        return
    end
    local okw, err = pcall(function()
        f:write("# phase=" .. tostring(phase) .. " vm=" .. vm_tag() .. " n=" .. tostring(#steps) .. "\n")
        f:write("i,dt_ms,step,jerk\n")
        local n = #steps
        for i = 1, n do
            f:write(string.format("%d,%.3f,%.6f,%.4f\n", i, (dts[i] or 0) * 1000, steps[i] or 0, jerks[i] or 0))
        end
        f:close()
    end)
    if not okw then
        pcall(function() f:close() end)
        JLog("display", "csv write failed path=%s err=%s", tostring(path), tostring(err))
        return
    end
    JLog("display", "csv wrote %s n=%d", tostring(path), #steps)
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

        -- ---- sparse sim-tick samples (legacy, low rate) ----
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

        -- ---- wall-clock display metrics (looks-like-jitter) ----
        -- Cap stored samples to bound memory; stats use full counters where noted.
        local MAX_STORE = 3600 -- ~60s @60Hz
        local w_steps, w_jerks, w_dts = {}, {}, {}
        local w_last_x, w_last_z, w_last_t
        local w_sum_step, w_sum_jerk, w_n = 0, 0, 0
        local w_max_step, w_max_jerk = 0, 0
        local w_freeze_n = 0 -- dt_wall with step ~ 0 while previous had motion (stair hold)
        local w_print_every = 5.0
        local w_last_print = wall_now()
        local JERK_PRINT_MIN = 20 -- u/s spike print threshold (run ~6; spikes much higher on snap)

        local function reset_wall_stats()
            w_steps, w_jerks, w_dts = {}, {}, {}
            w_sum_step, w_sum_jerk, w_n = 0, 0, 0
            w_max_step, w_max_jerk = 0, 0
            w_freeze_n = 0
            w_last_x, w_last_z, w_last_t = nil, nil, nil
        end

        local function print_wall_stats(tag)
            if w_n == 0 then
                JLog("display", "%s phase=%s n=0", tag, phase)
                return
            end
            local ss = stats_of(w_steps)
            local js = stats_of(w_jerks)
            local ds = stats_of(w_dts)
            JLog("display",
                "%s phase=%s vm=%s n=%d step med/p90/max=%.4f/%.4f/%.4f jerk med/p90/max=%.2f/%.2f/%.2f dt_ms med/p90=%.2f/%.2f freeze_frac=%.2f",
                tag, phase, vm_tag(), w_n,
                ss.med, ss.p90, ss.max,
                js.med, js.p90, js.max,
                ds.med * 1000, ds.p90 * 1000,
                w_n > 0 and (w_freeze_n / w_n) or 0)
        end

        local function on_wall_sample(dt)
            if not inst:IsValid() then
                return
            end
            local now = wall_now()
            local x, y, z = inst.Transform:GetWorldPosition()
            if w_last_x ~= nil then
                local step = hypot2(x - w_last_x, z - w_last_z)
                local dt_w = now - w_last_t
                if dt_w < 1e-4 then
                    dt_w = (type(dt) == "number" and dt > 1e-4) and dt or 1e-4
                end
                local jerk = step / dt_w
                w_sum_step = w_sum_step + step
                w_sum_jerk = w_sum_jerk + jerk
                w_n = w_n + 1
                if step > w_max_step then w_max_step = step end
                if jerk > w_max_jerk then w_max_jerk = jerk end
                if step < 1e-4 and w_n > 1 then
                    w_freeze_n = w_freeze_n + 1
                end
                if #w_steps < MAX_STORE then
                    w_steps[#w_steps + 1] = step
                    w_jerks[#w_jerks + 1] = jerk
                    w_dts[#w_dts + 1] = dt_w
                end
                -- rare spike print (visual snap evidence)
                if jerk >= JERK_PRINT_MIN and step >= 0.05 then
                    JLog("jerk", "step=%.4f jerk=%.1f dt_ms=%.2f phase=%s xyz=%.3f,%.3f",
                        step, jerk, dt_w * 1000, phase, x, z)
                end
            end
            w_last_x, w_last_z, w_last_t = x, z, now

            if now - w_last_print >= w_print_every then
                w_last_print = now
                print_wall_stats("periodic")
            end
        end

        -- Prefer wall list (render-rate). Fallback: StartWallUpdatingComponent on a tiny driver.
        local pc = inst.components and inst.components.playercontroller
        if pc ~= nil and type(pc.OnWallUpdate) == "function" then
            local old_wall = pc.OnWallUpdate
            function pc:OnWallUpdate(dt, ...)
                if old_wall ~= nil then
                    old_wall(self, dt, ...)
                end
                if self.inst == inst then
                    on_wall_sample(dt)
                end
            end
            JLog("display", "hooked PlayerController:OnWallUpdate for wall metrics")
        else
            -- Minimal wall driver component
            local driver = {
                OnWallUpdate = function(_, dt)
                    on_wall_sample(dt)
                end,
            }
            if inst.StartWallUpdatingComponent then
                -- entityscript expects a component table with OnWallUpdate
                inst.components._jitter_display_driver = driver
                inst:StartWallUpdatingComponent(driver)
                JLog("display", "StartWallUpdatingComponent driver installed")
            else
                -- last resort: sim periodic (worse, not true wall)
                inst:DoPeriodicTask(0, function()
                    on_wall_sample(0)
                end)
                JLog("display", "fallback DoPeriodicTask(0) — not pure wall clock")
            end
        end

        -- Mode poll: print stats on prediction change.
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
                write_display_csv(phase, w_steps, w_jerks, w_dts)
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
            write_display_csv(phase, w_steps, w_jerks, w_dts)
            do_flush("event")
        end)

        inst:ListenForEvent("playerdeactivated", function()
            print_wall_stats("deactivated")
            write_display_csv(phase, w_steps, w_jerks, w_dts)
            do_flush("deactivated")
        end)
    end)
end)

print("[JITTER][LUA] loaded — wall display metrics on; PushEvent('jitter_probe_flush') dumps authority ring + display CSV")
