local function assert_equal(actual, expected, message)
    if actual ~= expected then
        error(string.format("%s: expected %s, got %s", message, tostring(expected), tostring(actual)))
    end
end

local function assert_truthy(value, message)
    if not value then
        error(message)
    end
end

local function run_case(name, fork_result, opts)
    opts = opts or {}
    local old_print = print
    local old_save_game = _G.SaveGame
    local old_game_injector = _G.GameInjector
    local old_the_world = _G.TheWorld
    local old_the_net = _G.TheNet
    local old_shard_index = _G.ShardGameIndex
    local old_all_players = _G.AllPlayers
    local old_deepcopy = _G.deepcopy

    local events = {
        callback_count = 0,
        cleanup_count = 0,
        exit_count = 0,
        wait_count = 0,
        poll_count = 0,
        save_count = 0,
        start_world_save_count = 0,
        end_world_save_count = 0,
        increment_snapshot_count = 0,
        truncate_snapshots_count = 0,
        set_current_snapshot_count = 0,
        shard_save_count = 0,
        write_time_file_count = 0,
        last_isshutdown = nil,
        timeout_tasks = {},
        periodic_task = nil,
        poll_status_queue = opts.poll_status_queue,
    }

    local function restore_globals()
        print = old_print
        _G.SaveGame = old_save_game
        _G.GameInjector = old_game_injector
        _G.TheWorld = old_the_world
        _G.TheNet = old_the_net
        _G.ShardGameIndex = old_shard_index
        _G.AllPlayers = old_all_players
        _G.deepcopy = old_deepcopy
    end

    print = function(...)
        return ...
    end

    _G.AllPlayers = opts.all_players or {}
    _G.deepcopy = function(v)
        return v
    end

    _G.TheWorld = {
        meta = {
            session_identifier = "session-test",
        },
        topology = {
            overrides = { foo = "bar" },
        },
        DoTaskInTime = function(_, delay, fn)
            local task = { delay = delay, fn = fn }
            table.insert(events.timeout_tasks, task)
            return task
        end,
        DoPeriodicTask = function(_, delay, fn)
            events.periodic_task = { delay = delay, fn = fn }
            return events.periodic_task
        end,
    }

    _G.TheNet = {
        StartWorldSave = function()
            events.start_world_save_count = events.start_world_save_count + 1
        end,
        EndWorldSave = function()
            events.end_world_save_count = events.end_world_save_count + 1
        end,
        IncrementSnapshot = function()
            events.increment_snapshot_count = events.increment_snapshot_count + 1
        end,
        TruncateSnapshots = function(_, session_id)
            events.truncate_snapshots_count = events.truncate_snapshots_count + 1
            events.last_truncate_session = session_id
        end,
        TruncateSnapshotsInClusterSlot = function()
            events.truncate_snapshots_count = events.truncate_snapshots_count + 1
        end,
        SetCurrentSnapshot = function()
            events.set_current_snapshot_count = events.set_current_snapshot_count + 1
        end,
    }

    _G.ShardGameIndex = {
        GetGenOptions = function()
            return { overrides = {} }
        end,
        GetSlot = function()
            return 1
        end,
        GetShard = function()
            return "Master"
        end,
        Save = function(_, cb)
            events.shard_save_count = events.shard_save_count + 1
            if cb ~= nil then
                cb()
            end
        end,
        WriteTimeFile = function(_, cb)
            events.write_time_file_count = events.write_time_file_count + 1
            if cb ~= nil then
                cb()
            end
        end,
    }

    local poll_index = 0
    _G.GameInjector = {
        DS_LUAJIT_fork_save = function()
            return fork_result
        end,
        DS_LUAJIT_fork_save_exit = function()
            events.exit_count = events.exit_count + 1
        end,
        DS_LUAJIT_fork_save_cleanup = function()
            events.cleanup_count = events.cleanup_count + 1
        end,
        DS_LUAJIT_fork_save_wait = function()
            events.wait_count = events.wait_count + 1
        end,
        DS_LUAJIT_fork_save_poll = function()
            events.poll_count = events.poll_count + 1
            local queue = events.poll_status_queue
            if queue ~= nil and #queue > 0 then
                poll_index = poll_index + 1
                local status = queue[math.min(poll_index, #queue)]
                return status
            end
            return opts.poll_status or "idle"
        end,
    }

    _G.SaveGame = function(isshutdown, callback, ...)
        events.save_count = events.save_count + 1
        events.last_isshutdown = isshutdown
        if opts.raise_error then
            error("save failed")
        end
        -- Vanilla SaveGame internal callback mutates snapshot state.
        -- Child path must no-op these; parent path must still perform them.
        if _G.TheNet then
            if #(_G.AllPlayers or {}) <= 0 then
                _G.TheNet:TruncateSnapshots("session-test")
            end
            _G.TheNet:IncrementSnapshot()
            _G.TheNet:EndWorldSave()
        end
        if callback ~= nil then
            callback("save-finished", ...)
        end
        return "default-save", isshutdown
    end
    package.loaded["scripts.fork_save"] = nil
    local chunk, load_err = loadfile("Mod/scripts/fork_save.lua")
    if not chunk then
        restore_globals()
        error(load_err)
    end
    chunk()

    local callback_args = nil
    local function callback(...)
        events.callback_count = events.callback_count + 1
        callback_args = { ... }
    end

    local isshutdown = opts.isshutdown
    local ok, result = pcall(_G.SaveGame, isshutdown, callback, "extra")
    if not ok then
        restore_globals()
        error(string.format("%s: unexpected SaveGame error: %s", name, tostring(result)))
    end

    local function drain_tasks_until(predicate, limit)
        limit = limit or 20
        for _ = 1, limit do
            if predicate() then
                return true
            end
            if #events.timeout_tasks == 0 then
                return predicate()
            end
            local task = table.remove(events.timeout_tasks, 1)
            task.fn()
        end
        return predicate()
    end

    if isshutdown then
        assert_equal(events.wait_count, 1, name .. " should wait for previous fork child")
        assert_equal(events.save_count, 1, name .. " should save on main process")
        assert_equal(events.last_isshutdown, true, name .. " should pass isshutdown=true")
        assert_equal(events.callback_count, 1, name .. " should invoke callback through main process save")
        assert_equal(events.exit_count, 0, name .. " should not exit child on isshutdown")
        assert_equal(#events.timeout_tasks, 0, name .. " should not arm child timeout on isshutdown")
    elseif fork_result == "unsupported" or fork_result == "other" then
        assert_equal(events.wait_count, 0, name .. " should not wait when forking")
        assert_equal(events.save_count, 1, name .. " should fall back to default save")
        assert_equal(events.callback_count, 1, name .. " should invoke callback through default save")
        assert_equal(events.exit_count, 0, name .. " should not exit child")
    elseif fork_result == "parent" then
        assert_equal(events.wait_count, 0, name .. " should not block wait when forking")
        assert_equal(events.save_count, 0, name .. " should skip default save in parent")
        assert_equal(events.callback_count, 0, name .. " should not invoke callback synchronously")
        assert_equal(events.start_world_save_count, 1, name .. " should StartWorldSave in parent")
        assert_equal(events.exit_count, 0, name .. " should not exit in parent path")
        assert_truthy(#events.timeout_tasks >= 1, name .. " should schedule async child poll")

        local completed = drain_tasks_until(function()
            return events.callback_count > 0
        end)
        assert_truthy(completed, name .. " should finish parent postsave asynchronously")
        assert_truthy(events.poll_count >= 1, name .. " should poll child status")
        assert_equal(events.increment_snapshot_count, 1, name .. " should IncrementSnapshot after child exits")
        assert_equal(events.shard_save_count, 1, name .. " should ShardGameIndex:Save after child exits")
        assert_equal(events.write_time_file_count, 1, name .. " should WriteTimeFile after shard save")
        assert_equal(events.end_world_save_count, 1, name .. " should EndWorldSave before external callback")
        assert_equal(events.callback_count, 1, name .. " should invoke external callback after postsave")

        if opts.expect_truncate then
            assert_equal(events.truncate_snapshots_count, 1, name .. " should TruncateSnapshots when empty")
            assert_equal(events.last_truncate_session, "session-test", name .. " should truncate current session")
        else
            assert_equal(events.truncate_snapshots_count, 0, name .. " should not truncate when players present")
        end
    elseif fork_result == "child" and opts.raise_error then
        assert_equal(events.wait_count, 0, name .. " should not wait when forking")
        assert_equal(events.save_count, 1, name .. " should attempt save in child path")
        assert_equal(events.callback_count, 0, name .. " should not invoke external callback after save error")
        assert_equal(events.exit_count, 1, name .. " should exit once after child save error")
        assert_equal(events.increment_snapshot_count, 0, name .. " child must not IncrementSnapshot")
        assert_equal(events.truncate_snapshots_count, 0, name .. " child must not TruncateSnapshots")
    elseif fork_result == "child" then
        assert_equal(events.wait_count, 0, name .. " should not wait when forking")
        assert_equal(events.save_count, 1, name .. " should execute default save in child path")
        assert_equal(events.callback_count, 0, name .. " child should not invoke external callback")
        assert_equal(events.exit_count, 1, name .. " should exit once after child save completes")
        assert_equal(events.increment_snapshot_count, 0, name .. " child must not IncrementSnapshot")
        assert_equal(events.truncate_snapshots_count, 0, name .. " child must not TruncateSnapshots")
        assert_equal(events.set_current_snapshot_count, 0, name .. " child must not SetCurrentSnapshot")
        assert_equal(events.end_world_save_count, 0, name .. " child must not EndWorldSave")
        assert_truthy(#events.timeout_tasks >= 1, name .. " should arm child timeout task")
        assert_equal(events.timeout_tasks[1].delay, 30, name .. " should arm 30 second timeout")
    else
        restore_globals()
        error("unhandled test case: " .. tostring(fork_result))
    end

    assert_truthy(events.periodic_task ~= nil, name .. " should register periodic cleanup")
    assert_equal(events.periodic_task.delay, 10, name .. " should clean up every 10 seconds")
    events.periodic_task.fn()
    assert_equal(events.cleanup_count, 1, name .. " should invoke cleanup task")

    restore_globals()
    print("PASS: " .. name)
end

run_case("unsupported falls back", "unsupported")
run_case("parent postsaves after child idle", "parent", {
    poll_status_queue = { "running", "idle" },
    all_players = { { userid = "user1" } },
    expect_truncate = false,
})
run_case("parent truncates when empty", "parent", {
    poll_status = "idle",
    all_players = {},
    expect_truncate = true,
})
run_case("child saves and exits", "child")
run_case("other result falls back", "other")
run_case("child save failure exits", "child", { raise_error = true })
run_case("isshutdown uses main process", "parent", { isshutdown = true })
run_case("isshutdown ignores child fork result", "child", { isshutdown = true })

print("fork_save_spec: all tests passed")
