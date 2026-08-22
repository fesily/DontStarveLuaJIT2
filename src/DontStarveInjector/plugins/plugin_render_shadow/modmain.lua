-- plugins/plugin_render_shadow/modmain.lua
-- Lua only pushes TheWorld.state. Native Evaluate is the sun formula.

local injector = GameInjector

local function export(name)
    if injector and injector[name] then
        return injector[name]
    end
    return rawget(_G, name)
end

local sun_enabled = false
local length_boost = 1.0
local northern = true
local last_raw = nil
local last_pid = nil
local last_p = nil
local last_static = nil

local function rebuild_static()
    local sm = TheWorld and TheWorld.ShadowManager
    if sm and sm.GenerateStaticShadows then
        sm:GenerateStaticShadows()
    end
end

local function is_cave()
    return TheWorld ~= nil and TheWorld.HasTag ~= nil and TheWorld:HasTag("cave")
end

local function apply()
    if TheNet and TheNet.IsDedicated and TheNet:IsDedicated() then
        sun_enabled = false
        return
    end
    local en
    length_boost = 1.0
    northern = true
    if type(GetModConfigData) == "function" then
        en = GetModConfigData("ShadowSunDrive")
        length_boost = tonumber(GetModConfigData("ShadowLengthBoost")) or 1.0
        northern = (GetModConfigData("ShadowHemisphere") or "north") ~= "south"
    end
    sun_enabled = en and true or false
    last_raw = nil
    last_pid = nil
    last_p = nil
    last_static = nil
    local sil = false
    if type(GetModConfigData) == "function" then
        sil = GetModConfigData("ShadowSilhouetteBatch") and true or false
    end
    local set_sil = export("DS_LUAJIT_shadow_set_silhouette")
    if set_sil then
        set_sil(sil and 1 or 0)
    end
    local set_ellipse = export("DS_LUAJIT_shadow_set_ellipse")
    if set_ellipse then
        set_ellipse(sil and 0 or 1)
    end
    local set_boost = export("DS_LUAJIT_shadow_set_length_boost")
    if set_boost then
        set_boost(length_boost)
    end
    local set_hemi = export("DS_LUAJIT_shadow_set_hemisphere")
    if set_hemi then
        set_hemi(northern and 1 or 0)
    end
    local set_enabled = export("DS_LUAJIT_shadow_set_enabled")
    if set_enabled then
        set_enabled(sun_enabled)
    end
    print(string.format("[render.shadow] apply sil=%s sun=%s ellipse=%s boost=%.2f hemi=%s",
        tostring(sil), tostring(sun_enabled), sil and "off" or "on", length_boost,
        northern and "north" or "south"))

end

local function world_flags(st)
    local f = 0
    if st.isfullmoon then
        f = f + 1
    end
    if st.season == "winter" then
        f = f + 2
    elseif st.season == "summer" then
        f = f + 4
    end
    local pr = st.precipitation
    if pr == "rain" or pr == "snow" then
        f = f + 8
    end
    return f
end

local function publish()
    local set_world = export("DS_LUAJIT_shadow_set_world")
    if not set_world then
        return
    end
    if is_cave() then
        if last_raw ~= "cave" then
            last_raw, last_pid, last_p = "cave", nil, nil
            set_world(2, 0, 0, 0)
        end
        return
    end
    local st = TheWorld and TheWorld.state
    if not st then
        return
    end
    local phase = st.phase
    local pid = 0
    if phase == "dusk" then
        pid = 1
    elseif phase == "night" then
        pid = 2
    end
    local p = tonumber(st.timeinphase) or 0
    local t = tonumber(st.time) or 0
    if last_pid == pid and last_p and last_p > 0.9 and p < 0.1 then
        p = 1
    end
    local flags = world_flags(st)
    local raw = string.format("%d/%.4f/%.4f/%d", pid, p, t, flags)
    if raw == last_raw then
        return
    end
    last_raw, last_pid, last_p = raw, pid, p
    set_world(pid, math.floor(p * 10000 + 0.5), math.floor(t * 10000 + 0.5), flags)
    if sun_enabled then
        local bucket = math.floor(p * 16)
        if last_static ~= bucket then
            last_static = bucket
            rebuild_static()
        end
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
    TheWorld:ListenForEvent("clocktick", function()
        publish()
    end)
    local dt = (FRAMES ~= nil and FRAMES) or (1 / 30)
    TheWorld:DoPeriodicTask(dt, publish)
end)
