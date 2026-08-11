-- client_smooth.lua
-- Display-only extrapolation for the local player when movement prediction is OFF.
if TheNet and TheNet:IsDedicated() then
    return
end

local MAX_EXTRAP_DIST = 1.2
local SNAP_EPS = 0.05
local TELEPORT_EPS = 3.0
local BLEND_TIME = 0.08
local DIR_DEADZONE = 1e-3
local EPSILON_DISP = 1e-3

local function lerp(a, b, u)
    return a + (b - a) * u
end

local function clamp01(u)
    if u < 0 then
        return 0
    end
    if u > 1 then
        return 1
    end
    return u
end

local function pred_on()
    return Profile ~= nil
        and Profile.GetMovementPredictionEnabled ~= nil
        and Profile:GetMovementPredictionEnabled()
end

local function get_speed(inst)
    if inst.player_classified ~= nil and inst.player_classified.runspeed ~= nil then
        local v = inst.player_classified.runspeed:value()
        if type(v) == "number" and v > 0 then
            return v
        end
    end
    return (TUNING and TUNING.WILSON_RUN_SPEED) or 6
end

local function should_run(inst)
    if ThePlayer == nil or inst ~= ThePlayer then
        return false
    end
    if pred_on() then
        return false
    end
    if inst.components ~= nil and inst.components.locomotor ~= nil then
        return false
    end
    if inst:HasTag("playerghost") then
        return false
    end
    if inst.GetCurrentPlatform ~= nil and inst:GetCurrentPlatform() ~= nil then
        return false
    end
    return true
end

local function attach(inst)
    local st = {
        walking = false,
        dir_x = 0,
        dir_z = 0,
        auth_x = 0,
        auth_y = 0,
        auth_z = 0,
        auth_t = 0,
        disp_x = 0,
        disp_z = 0,
        wrote = false,
        blend_t = 0,
        blend_from_x = 0,
        blend_from_z = 0,
        active = false,
        disabled = false,

    }

    local function reanchor(x, y, z, now, blend)
        if blend and st.wrote then
            st.blend_from_x, st.blend_from_z = st.disp_x, st.disp_z
            st.blend_t = BLEND_TIME
        else
            st.blend_t = 0
        end
        st.auth_x, st.auth_y, st.auth_z = x, y, z
        st.auth_t = now
        st.disp_x, st.disp_z = x, z
    end

    local function hard_restore()
        if st.active then
            inst.Transform:SetPosition(st.auth_x, st.auth_y, st.auth_z)
        end
        st.wrote = false
        st.walking = false
        st.active = false
        st.blend_t = 0
    end

    do
        local x, y, z = inst.Transform:GetWorldPosition()
        reanchor(x, y, z, GetTime(), false)
    end

    local pc = inst.components.playercontroller
    if pc ~= nil then
        local old_remote = pc.RemoteDirectWalking
        local old_stop = pc.RemoteStopWalking
        local old_wall = pc.OnWallUpdate

        if type(old_remote) == "function" then
            function pc:RemoteDirectWalking(x, z, ...)
                if self.inst == inst then
                    st.dir_x, st.dir_z = x or 0, z or 0
                    st.walking = (math.abs(st.dir_x) + math.abs(st.dir_z)) > DIR_DEADZONE
                end
                return old_remote(self, x, z, ...)
            end
        end

        if type(old_stop) == "function" then
            function pc:RemoteStopWalking(...)
                if self.inst == inst then
                    st.walking = false
                end
                return old_stop(self, ...)
            end
        end

        function pc:OnWallUpdate(dt, ...)
            if old_wall ~= nil then
                old_wall(self, dt, ...)
            end
            if self.inst ~= inst then
                return
            end

            local ok, err = pcall(function()
                if st.disabled then
                    return
                end

                if not should_run(inst) then
                    if st.active then
                        hard_restore()
                    end
                    return
                end

                st.active = true
                local now = GetTime()
                local cx, cy, cz = inst.Transform:GetWorldPosition()

                -- Teleport / large external move: hard re-anchor, no blend.
                local d_auth = math.sqrt((cx - st.auth_x) ^ 2 + (cz - st.auth_z) ^ 2)
                if d_auth > TELEPORT_EPS then
                    reanchor(cx, cy, cz, now, false)
                    st.wrote = false
                    return
                end

                -- Snap detection: engine kept our display write, or new authority.
                local d_exp = math.sqrt((cx - st.disp_x) ^ 2 + (cz - st.disp_z) ^ 2)
                if st.wrote and d_exp < EPSILON_DISP then
                    -- still our display write
                elseif d_auth > SNAP_EPS then
                    reanchor(cx, cy, cz, now, true)
                end

                -- Not walking: finish any soft blend toward auth, then hold.
                if not st.walking then
                    if st.blend_t > 0 then
                        st.blend_t = math.max(0, st.blend_t - dt)
                        local u = clamp01(1 - (st.blend_t / BLEND_TIME))
                        local dx = lerp(st.blend_from_x, st.auth_x, u)
                        local dz = lerp(st.blend_from_z, st.auth_z, u)
                        inst.Transform:SetPosition(dx, st.auth_y, dz)
                        st.disp_x, st.disp_z = dx, dz
                        st.wrote = true
                    end
                    return
                end

                local age = now - st.auth_t
                if age < 0 then
                    age = 0
                end

                local len = math.sqrt(st.dir_x * st.dir_x + st.dir_z * st.dir_z)
                if len < DIR_DEADZONE then
                    return
                end

                local nx, nz = st.dir_x / len, st.dir_z / len
                local speed = get_speed(inst)
                local dist = speed * age
                if dist > MAX_EXTRAP_DIST then
                    dist = MAX_EXTRAP_DIST
                end

                local ex = st.auth_x + nx * dist
                local ez = st.auth_z + nz * dist

                if st.blend_t > 0 then
                    st.blend_t = math.max(0, st.blend_t - dt)
                    local u = clamp01(1 - (st.blend_t / BLEND_TIME))
                    ex = lerp(st.blend_from_x, ex, u)
                    ez = lerp(st.blend_from_z, ez, u)
                end

                -- Y always from last auth; never extrapolate vertical.
                inst.Transform:SetPosition(ex, st.auth_y, ez)
                st.disp_x, st.disp_z = ex, ez
                st.wrote = true
            end)

            if not ok then
                print("[client.smooth] error: " .. tostring(err))
                hard_restore()
                st.disabled = true
            end
        end
    end

    inst:ListenForEvent("enablemovementprediction", function(_, enable)
        if enable then
            hard_restore()
        end
    end)

    inst:ListenForEvent("playerdeactivated", function()
        hard_restore()
    end)
end

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then
            return
        end
        -- Always attach wrappers so mid-session pred OFF still works.
        -- should_run gates the wall loop until prediction is actually off.
        attach(inst)
    end)
end)

print("[client.smooth] scripts loaded")
