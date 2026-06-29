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
    local old_print = print
    local old_save_game = _G.SaveGame
    local old_game_injector = _G.GameInjector
    local old_the_world = _G.TheWorld

    local events = {
        callback_count = 0,
        cleanup_count = 0,
        exit_count = 0,
        save_count = 0,
        timeout_task = nil,
        periodic_task = nil,
    }

    local function restore_globals()
        print = old_print
        _G.SaveGame = old_save_game
        _G.GameInjector = old_game_injector
        _G.TheWorld = old_the_world
    end

    print = function(...)
        return ...
    end

    _G.TheWorld = {
        DoTaskInTime = function(_, delay, fn)
            events.timeout_task = { delay = delay, fn = fn }
        end,
        DoPeriodicTask = function(_, delay, fn)
            events.periodic_task = { delay = delay, fn = fn }
        end,
    }

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
    }

    _G.SaveGame = function(isshutdown, callback, ...)
        events.save_count = events.save_count + 1
        if opts and opts.raise_error then
            error("save failed")
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

    local ok, result = pcall(_G.SaveGame, false, callback, "extra")
    restore_globals()
    if not ok then
        error(string.format("%s: unexpected SaveGame error: %s", name, tostring(result)))
    end

    if fork_result == "unsupported" or fork_result == "other" then
        assert_equal(events.save_count, 1, name .. " should fall back to default save")
        assert_equal(events.callback_count, 1, name .. " should invoke callback through default save")
        assert_equal(events.exit_count, 0, name .. " should not exit child")
    elseif fork_result == "parent" then
        assert_equal(events.save_count, 0, name .. " should skip default save in parent")
        assert_equal(events.callback_count, 1, name .. " should invoke callback in parent path")
        assert_equal(events.exit_count, 0, name .. " should not exit in parent path")
    elseif fork_result == "child" and opts and opts.raise_error then
        assert_equal(events.save_count, 1, name .. " should attempt save in child path")
        assert_equal(events.callback_count, 0, name .. " should not invoke callback after save error")
        assert_equal(events.exit_count, 1, name .. " should exit once after child save error")
    elseif fork_result == "child" then
        assert_equal(events.save_count, 1, name .. " should execute default save in child path")
        assert_equal(events.callback_count, 1, name .. " should invoke callback from child path")
        assert_equal(events.exit_count, 1, name .. " should exit once after child save completes")
        assert_truthy(events.timeout_task ~= nil, name .. " should arm child timeout task")
        assert_equal(events.timeout_task.delay, 30, name .. " should arm 30 second timeout")
        assert_truthy(callback_args ~= nil and callback_args[1] == "save-finished", name .. " should forward callback args")
    else
        error("unhandled test case: " .. tostring(fork_result))
    end

    assert_truthy(events.periodic_task ~= nil, name .. " should register periodic cleanup")
    assert_equal(events.periodic_task.delay, 10, name .. " should clean up every 10 seconds")
    events.periodic_task.fn()
    assert_equal(events.cleanup_count, 1, name .. " should invoke cleanup task")

    print("PASS: " .. name)
end

run_case("unsupported falls back", "unsupported")
run_case("parent skips save", "parent")
run_case("child saves and exits", "child")
run_case("other result falls back", "other")
run_case("child save failure exits", "child", { raise_error = true })

print("fork_save_spec: all tests passed")
