local GameInjector = _G.rawget(_G, "GameInjector")
if not GameInjector or not GameInjector.DS_LUAJIT_fork_save then
    return
end

local fork_save = GameInjector.DS_LUAJIT_fork_save
local fork_save_exit = GameInjector.DS_LUAJIT_fork_save_exit
local fork_save_cleanup = GameInjector.DS_LUAJIT_fork_save_cleanup

local old_SaveGame = _G.SaveGame
if type(old_SaveGame) ~= "function" then
    print("[fork_save] SaveGame is not ready")
    return
end

local in_fork_save = false

local function run_default_save(isshutdown, callback, ...)
    return old_SaveGame(isshutdown, callback, ...)
end

_G.SaveGame = function(isshutdown, callback, ...)
    if in_fork_save then
        return run_default_save(isshutdown, callback, ...)
    end

    local result = fork_save()

    if result == "unsupported" then
        return run_default_save(isshutdown, callback, ...)
    elseif result == "parent" then
        if callback ~= nil then
            callback()
        end
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

        local function on_saved(...)
            if callback ~= nil then
                callback(...)
            end
            exit_child()
        end

        local success, err = pcall(old_SaveGame, isshutdown, on_saved, ...)
        if not success then
            print("[fork_save] child: SaveGame failed: " .. tostring(err))
            exit_child()
            return
        end

        if _G.TheWorld then
            _G.TheWorld:DoTaskInTime(30, function()
                print("[fork_save] child: SaveGame callback timeout")
                exit_child()
            end)
        end
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
