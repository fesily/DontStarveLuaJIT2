-- client_anim.lua — pred-OFF local run/idle (client.anim).
--
-- Stock EnableMovementPrediction(false) clears SG + locomotor → anim is 100%
-- network. While pred OFF and not busy:
--   1) native: force Deserialize local_a0 (skip PlayMode/AnimHash/AnimTime)
--   2) Lua: PlayAnimation(run_* or idle) from input (no SetMotorVel)
-- Busy / actions / pred ON: release ownership so network drives anims.
if TheNet and TheNet:IsDedicated() then
    return
end

local GameInjector = _G.rawget(_G, "GameInjector")
if not GameInjector then
    print("[client.anim] GameInjector missing — inactive")
    return
end

if type(GameInjector.DS_LUAJIT_client_anim_set_own) ~= "function" then
    print("[client.anim] native exports missing — rebuild/replace plugin_client_anim.dll")
    return
end

local function set_own(on)
    GameInjector.DS_LUAJIT_client_anim_set_own(on and true or false)
end

local function bind_player(inst)
    local ent = inst and inst.entity
    if not ent then
        return false
    end
    local raw = ent
    if GameInjector.DS_LUAJIT_entity_get_raw_ptr then
        local ok_raw, ptr = pcall(GameInjector.DS_LUAJIT_entity_get_raw_ptr, ent)
        if ok_raw and ptr then
            raw = ptr
        end
    end
    if not GameInjector.DS_LUAJIT_client_anim_bind_player then
        return false
    end
    local ok, res = pcall(GameInjector.DS_LUAJIT_client_anim_bind_player, raw)
    if not (ok and res) and raw ~= ent then
        ok, res = pcall(GameInjector.DS_LUAJIT_client_anim_bind_player, ent)
        raw = ent
    end
    if ok and res then
        local a0_enter = GameInjector.DS_LUAJIT_client_anim_enter_count
            and GameInjector.DS_LUAJIT_client_anim_enter_count() or -1
        local a0_match = GameInjector.DS_LUAJIT_client_anim_match_count
            and GameInjector.DS_LUAJIT_client_anim_match_count() or -1
        print(string.format(
            "[client.anim] bound raw=%s installed=%s enter=%s match=%s native_own=%s",
            tostring(raw),
            tostring(GameInjector.DS_LUAJIT_client_anim_is_installed
                and GameInjector.DS_LUAJIT_client_anim_is_installed() or 0),
            tostring(a0_enter), tostring(a0_match),
            tostring(GameInjector.DS_LUAJIT_client_anim_get_own
                and GameInjector.DS_LUAJIT_client_anim_get_own() or -1)))
        return true
    end
    print(string.format("[client.anim] bind failed ok=%s res=%s raw=%s",
        tostring(ok), tostring(res), tostring(raw)))
    return false
end

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

local function pick_idle_anim(inst)
    if inst:HasTag("playerghost") then
        return "idle"
    end
    local inv = inst.replica and inst.replica.inventory
    if inv and inv.IsHeavyLifting and inv:IsHeavyLifting() then
        return "heavy_idle"
    end
    return "idle_loop"
end

local function drive_local_locomote(inst, moving, dir)
    local as = inst.AnimState
    if not as or not as.IsCurrentAnimation or not as.PlayAnimation then
        return
    end
    if moving then
        local pre, loop = pick_locomote_anims(inst)
        if dir and inst.Transform and inst.Transform.SetRotation then
            local rot = -math.atan2(dir.z, dir.x) / DEGREES
            inst.Transform:SetRotation(rot)
        end
        if not (as:IsCurrentAnimation(loop) or as:IsCurrentAnimation(pre)) then
            as:PlayAnimation(pre)
            if as.PushAnimation then
                as:PushAnimation(loop, true)
            end
        elseif as:IsCurrentAnimation(pre) and as.AnimDone and as:AnimDone() then
            as:PlayAnimation(loop, true)
        end
        return
    end
    local idle = pick_idle_anim(inst)
    if not as:IsCurrentAnimation(idle) then
        as:PlayAnimation(idle, true)
    end
end

print("[client.anim] loaded")

AddPlayerPostInit(function(inst)
    inst:DoTaskInTime(0, function(inst)
        if ThePlayer ~= inst then
            return
        end
        bind_player(inst)
        for _, delay in ipairs({0.5, 1.5, 3.0}) do
            inst:DoTaskInTime(delay, function(i)
                if ThePlayer == i then
                    bind_player(i)
                end
            end)
        end

        local last_own = false
        local tick_i = 0
        inst:DoPeriodicTask(0, function()
            if not inst:IsValid() or ThePlayer ~= inst then
                set_own(false)
                return
            end
            tick_i = tick_i + 1
            local pred = Profile and Profile.GetMovementPredictionEnabled
                and Profile:GetMovementPredictionEnabled()
            local has_loco = inst.components and inst.components.locomotor ~= nil
            local dir = get_move_dir()
            local moving = dir ~= nil
            local pc = inst.components and inst.components.playercontroller
            if pc and (pc.directwalking or pc.dragwalking) then
                moving = true
            end
            local busy = is_busy_for_anim(inst)
            local want_own = (not pred) and (not has_loco) and (not busy)

            if want_own ~= last_own then
                print(string.format("[client.anim] own=%s moving=%s busy=%s pred=%s",
                    tostring(want_own), tostring(moving), tostring(busy), tostring(pred)))
                last_own = want_own
            end
            set_own(want_own)
            if want_own then
                drive_local_locomote(inst, moving, dir)
            end
            if tick_i % 60 == 0 then
                local a0_enter = GameInjector.DS_LUAJIT_client_anim_enter_count
                    and GameInjector.DS_LUAJIT_client_anim_enter_count() or -1
                local a0_match = GameInjector.DS_LUAJIT_client_anim_match_count
                    and GameInjector.DS_LUAJIT_client_anim_match_count() or -1
                print(string.format(
                    "[client.anim] stats enter=%s match=%s native_own=%s moving=%s",
                    tostring(a0_enter), tostring(a0_match),
                    tostring(GameInjector.DS_LUAJIT_client_anim_get_own
                        and GameInjector.DS_LUAJIT_client_anim_get_own() or -1),
                    tostring(moving)))
            end
        end)

        inst:ListenForEvent("playerdeactivated", function()
            set_own(false)
        end)
    end)
end)
