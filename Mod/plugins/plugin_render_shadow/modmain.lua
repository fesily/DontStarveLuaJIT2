-- plugins/plugin_render_shadow/modmain.lua
-- ShadowSunDrive / ShadowLengthBoost → C exports; periodic TheWorld.state feed.
-- Non-Windows GetModConfigData returns nil (HookGetModConfigData).

local injector = GameInjector

local function export(name)
    if injector and injector[name] then
        return injector[name]
    end
    return rawget(_G, name)
end

local function apply()
    local en
    local boost = 1.0
    if type(GetModConfigData) == "function" then
        en = GetModConfigData("ShadowSunDrive")
        boost = GetModConfigData("ShadowLengthBoost") or 1.0
    end
    local set_boost = export("DS_LUAJIT_shadow_set_length_boost")
    if set_boost then
        set_boost(boost)
    end
    local set_enabled = export("DS_LUAJIT_shadow_set_enabled")
    if set_enabled then
        set_enabled(en and true or false)
    end
end

-- World state feed (day/dusk/night) — minimal; Task 4 may expand
local function push_state()
    if not TheWorld or not TheWorld.state then
        return
    end
    local set_state = export("DS_LUAJIT_shadow_set_state")
    if not set_state then
        return
    end
    local st = TheWorld.state
    local phase = st.phase
    local pid = 0
    if phase == "dusk" then
        pid = 1
    elseif phase == "night" then
        pid = 2
    end
    local progress = st.timeinphase or 0
    local moon = st.isfullmoon and 1 or 0
    set_state(pid, progress, moon)
end

apply()
AddSimPostInit(function()
    if TheWorld then
        TheWorld:DoPeriodicTask(0.5, push_state)
        push_state()
    end
end)
