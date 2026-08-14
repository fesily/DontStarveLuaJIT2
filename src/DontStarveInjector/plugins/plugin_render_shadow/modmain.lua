-- plugins/plugin_render_shadow/modmain.lua
-- Yaw integrates locally (FRAMES/TOTAL_DAY_TIME). Origin is locked once
-- from 3 stable clocktick data.time samples (HUD clock), not from p=0.

local injector = GameInjector

local function export(name)
    if injector and injector[name] then
        return injector[name]
    end
    return rawget(_G, name)
end

local DAY = (TUNING and TUNING.TOTAL_DAY_TIME) or 480
local DT = (FRAMES ~= nil and FRAMES) or (1 / 30)
local MIN_STEP = 1 / 720
local STATIC_STEP = 1 / 16

local sun_enabled = false
local last_pub = nil
local last_static = nil
local p = 0
local ticks = 0
local last_log = 0
local clock_locked = false
local clock_ring = nil
local MAX_SEG = 2 / 16

local function rebuild_static()
    local sm = TheWorld and TheWorld.ShadowManager
    if sm and sm.GenerateStaticShadows then
        sm:GenerateStaticShadows()
    end
end

local function phase_id(phase)
    if phase == "dusk" then
        return 1
    end
    if phase == "night" then
        return 2
    end
    return 0
end

local function is_cave()
    return TheWorld ~= nil and TheWorld.HasTag ~= nil and TheWorld:HasTag("cave")
end

local function has_moonlight(st)
    if not st then
        return false
    end
    if st.isfullmoon then
        return true
    end
    local mp = st.moonphase
    return mp ~= nil and mp ~= "new"
end

local function apply()
    if TheNet and TheNet.IsDedicated and TheNet:IsDedicated() then
        sun_enabled = false
        return
    end
    local en
    local boost = 1.0
    local hemi = "north"
    if type(GetModConfigData) == "function" then
        en = GetModConfigData("ShadowSunDrive")
        boost = GetModConfigData("ShadowLengthBoost") or 1.0
        hemi = GetModConfigData("ShadowHemisphere") or "north"
    end
    sun_enabled = en and true or false
    last_pub = nil
    last_static = nil
    p = 0
    ticks = 0
    clock_locked = false
    clock_ring = nil
    local set_boost = export("DS_LUAJIT_shadow_set_length_boost")
    if set_boost then
        set_boost(math.floor((tonumber(boost) or 1) * 100 + 0.5))
    end
    local set_hemi = export("DS_LUAJIT_shadow_set_hemisphere")
    if set_hemi then
        set_hemi(hemi == "south" and 0 or 1)
    end
    local set_enabled = export("DS_LUAJIT_shadow_set_enabled")
    if set_enabled then
        set_enabled(sun_enabled)
    end
end

local function publish()
    local set_state = export("DS_LUAJIT_shadow_set_state")
    if not set_state then
        return
    end
    if is_cave() then
        if last_pub ~= "cave" then
            last_pub = "cave"
            set_state(2, 0, 0)
        end
        return
    end
    if last_pub ~= nil and type(last_pub) == "number" and math.abs(p - last_pub) < MIN_STEP then
        return
    end
    local st = TheWorld and TheWorld.state
    local phase = st and st.phase
    local moon = has_moonlight(st) and 1 or 0
    last_pub = p
    set_state(phase_id(phase), math.floor(p * 1000 + 0.5), moon)
    if sun_enabled then
        if last_static == nil or math.abs(p - last_static) >= STATIC_STEP then
            last_static = p
            rebuild_static()
        end
    end
end

local function circ_abs(a, b)
    local d = math.abs(a - b)
    if d > 0.5 then
        d = 1 - d
    end
    return d
end

local function lock_to(sample, why)
    p = sample
    last_pub = nil
    clock_locked = true
    clock_ring = { sample }
    print(string.format("[render.shadow] %s p=%.4f yaw=%.1f", why, p, -360 * p))
end

-- data.time is HUD clock (elapsedsegs/16). Need 3 smooth ticks so we skip
-- the client's default-dawn frames and the 0↔1 net snap.
local function consider_clock(raw)
    raw = tonumber(raw)
    if raw == nil then
        return
    end
    if raw < 0 then
        raw = 0
    elseif raw > 1 then
        raw = 1
    end
    clock_ring = clock_ring or {}
    clock_ring[#clock_ring + 1] = raw
    if #clock_ring > 3 then
        table.remove(clock_ring, 1)
    end
    if #clock_ring < 3 then
        return
    end
    if circ_abs(clock_ring[1], clock_ring[2]) > MAX_SEG
        or circ_abs(clock_ring[2], clock_ring[3]) > MAX_SEG then
        clock_ring = { clock_ring[2], clock_ring[3] }
        return
    end
    local sample = clock_ring[3]
    if not clock_locked then
        lock_to(sample, "lock")
    elseif circ_abs(p, sample) > MAX_SEG then
        lock_to(sample, "retarget")
    end
end

apply()
AddSimPostInit(function()
    if not TheWorld then
        return
    end
    if TheNet and TheNet.IsDedicated and TheNet:IsDedicated() then
        return
    end
    TheWorld:ListenForEvent("clocktick", function(_, data)
        if data then
            consider_clock(data.time)
        end
    end)
    TheWorld:DoPeriodicTask(DT, function()
        ticks = ticks + 1
        if not clock_locked then
            if ticks >= 90 then
                local st = TheWorld.state
                lock_to((st and tonumber(st.time)) or 0, "fallback")
            else
                return
            end
        end
        p = p + DT / DAY
        if p >= 1 then
            p = p - 1
        end
        publish()
        if ticks - last_log >= 150 then
            last_log = ticks
            print(string.format("[render.shadow] tick=%d p=%.4f yaw=%.1f locked=%s",
                ticks, p, -360 * p, clock_locked and "1" or "0"))
        end
    end)
end)
