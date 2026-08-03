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

-- TheNet APIs that mutate shared snapshot disk/state. Child must not run them:
-- SerializeWorldSession already writes the current snapshot file; Truncate/Increment
-- belong only to the live parent after the child exits (see SnapshotManager in engine).
-- TheNet is userdata, so we cannot assign methods on it; install a proxy table instead.
local CHILD_NET_NOOPS = {
    TruncateSnapshots = true,
    TruncateSnapshotsInClusterSlot = true,
    IncrementSnapshot = true,
    SetCurrentSnapshot = true,
    EndWorldSave = true,
}

local function run_default_save(isshutdown, callback, ...)
    return old_SaveGame(isshutdown, callback, ...)
end

local function with_child_net_noops(fn)
    local real_net = _G.TheNet
    local proxy = {}
    setmetatable(proxy, {
        __index = function(_, key)
            if CHILD_NET_NOOPS[key] then
                return function()
                    -- intentionally no-op in forked save child
                end
            end
            local value = real_net[key]
            if type(value) == "function" then
                return function(_, ...)
                    return value(real_net, ...)
                end
            end
            return value
        end,
    })

    _G.TheNet = proxy
    local ok, err = pcall(fn)
    _G.TheNet = real_net

    if not ok then
        error(err)
    end
end

-- Mirrors mainfunctions.lua SaveGame internal callback post-IO steps.
-- Must run only in the live parent process.
local function parent_finish_postsave(callback)
    local TheNet = _G.TheNet
    local TheWorld = _G.TheWorld
    local ShardGameIndex = _G.ShardGameIndex

    -- Vanilla: TruncateSnapshots(session) with omitted id uses GetCurrentSnapshot().
    -- Keeps [current - max_snapshots + 1, current], deletes the rest on disk.
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

        -- Disk write only. Snapshot retention / id advance happen in parent.
        local function on_saved()
            exit_child()
        end

        local save_args = { ... }
        local ok, err = pcall(function()
            with_child_net_noops(function()
                old_SaveGame(isshutdown, on_saved, unpack(save_args))
            end)
        end)

        if not ok then
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

_G.TheWorld:DoPeriodicTask(10, function()
    fork_save_cleanup()
end)
