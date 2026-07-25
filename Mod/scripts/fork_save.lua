local GameInjector = _G.rawget(_G, "GameInjector")
if not GameInjector or not GameInjector.DS_LUAJIT_fork_save then
    return
end

local fork_save = GameInjector.DS_LUAJIT_fork_save
local fork_save_exit = GameInjector.DS_LUAJIT_fork_save_exit
local fork_save_cleanup = GameInjector.DS_LUAJIT_fork_save_cleanup
local fork_save_wait = GameInjector.DS_LUAJIT_fork_save_wait
local fork_save_poll = GameInjector.DS_LUAJIT_fork_save_poll

local old_SaveGame = _G.SaveGame
if type(old_SaveGame) ~= "function" then
    print("[fork_save] SaveGame is not ready")
    return
end

local in_fork_save = false
local PARENT_POLL_INTERVAL = 1
local PARENT_POLL_TIMEOUT = 30

local function run_default_save(isshutdown, callback, ...)
    return old_SaveGame(isshutdown, callback, ...)
end

-- Mirrors mainfunctions.lua SaveGame internal callback post-IO steps.
local function parent_finish_postsave(callback)
    local TheNet = _G.TheNet
    local TheWorld = _G.TheWorld
    local ShardGameIndex = _G.ShardGameIndex

    if #_G.AllPlayers <= 0 then
        TheNet:TruncateSnapshots(TheWorld.meta.session_identifier)
    end
    TheNet:IncrementSnapshot()

    local function onwritetimefile()
        TheNet:EndWorldSave()
        if callback ~= nil then
            callback()
        end
    end

    local function onsaved()
        ShardGameIndex:WriteTimeFile(onwritetimefile)
    end

    local options = ShardGameIndex:GetGenOptions()
    options.overrides = _G.deepcopy(TheWorld.topology.overrides)
    ShardGameIndex:Save(onsaved)
end

local function parent_schedule_postsave(callback)
    local TheWorld = _G.TheWorld
    _G.TheNet:StartWorldSave()

    local elapsed = 0
    local function poll()
        local status = fork_save_poll()
        if status == "running" then
            elapsed = elapsed + PARENT_POLL_INTERVAL
            if elapsed >= PARENT_POLL_TIMEOUT then
                print("[fork_save] parent: child poll timeout, forcing wait")
                fork_save_wait()
                parent_finish_postsave(callback)
                return
            end
            TheWorld:DoTaskInTime(PARENT_POLL_INTERVAL, poll)
            return
        end

        print("[fork_save] parent: child finished, running postsave")
        parent_finish_postsave(callback)
    end

    print("[fork_save] parent: SaveGame deferred, waiting for child process")
    TheWorld:DoTaskInTime(PARENT_POLL_INTERVAL, poll)
end

_G.SaveGame = function(isshutdown, callback, ...)
    if in_fork_save then
        return run_default_save(isshutdown, callback, ...)
    end

    if isshutdown then
        fork_save_wait()
        print("[fork_save] isshutdown: use main process save")
        return run_default_save(isshutdown, callback, ...)
    end

    local result = fork_save()
    print("[fork_save] SaveGame result: " .. tostring(result))
    if result == "unsupported" then
        return run_default_save(isshutdown, callback, ...)
    elseif result == "parent" then
        parent_schedule_postsave(callback)
        return
    elseif result == "child" then
        in_fork_save = true
        local exited = false

        local function exit_child()
            if not exited then
                exited = true
                fork_save_exit()
            end
        end

        -- Parent owns external callback + memory postsave.
        -- Child only performs disk write, then exits.
        local function on_saved()
            exit_child()
        end

        local success, err = pcall(old_SaveGame, isshutdown, on_saved, ...)
        if not success then
            print("[fork_save] child: SaveGame failed: " .. tostring(err))
            exit_child()
            return
        end

        _G.TheWorld:DoTaskInTime(30, function()
            print("[fork_save] child: SaveGame callback timeout")
            exit_child()
        end)
        return
    else
        return run_default_save(isshutdown, callback, ...)
    end
end

if _G.TheWorld then
    _G.TheWorld:DoPeriodicTask(10, function()
        fork_save_cleanup()
    end)
end
