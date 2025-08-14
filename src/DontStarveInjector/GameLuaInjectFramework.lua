--[[
    1. Inject lua text into file afterload
    2. Replace lua text
]]

GameLuaInjector = {
    injectors = {},
    relocations = {}
}
local _M = GameLuaInjector

function _M.inject_module_text(target_filename, afterload)
    _M.injectors[target_filename] = {
        afterload = afterload,
    }
end

function _M.relocation_file(target_filename, new_filename)
    _M.relocations[target_filename] = new_filename
end

function _M.get(filename)
    return _M.injectors[filename]
end

local function do_inject(injector, m)
    if not injector then
        return
    end
    local afterload = injector.afterload
    if afterload then
        if type(afterload) == "function" then
            xpcall(afterload, debug.traceback, m)
        elseif type(afterload) == "string" then
            local f, err = loadstring(afterload)
            if f then
                xpcall(f, debug.traceback, m)
            else
                print("[luajit] Error in afterload function: " .. err)
            end
        end
    end
end

local inited = false;
function _M.init()
    if inited then
        return
    end
    inited = true
    local old_require = require
    function require(filename)
        filename = _M.relocations[filename] or filename
        local m = old_require(filename)
        local injector = _M.get(filename)
        do_inject(injector, m)
        return m
    end

    local old_kleiloadlua = kleiloadlua
    function kleiloadlua(filename, ...)
        filename = _M.relocations[filename] or filename
        local m = old_kleiloadlua(filename, ...)
        local injector = _M.get(filename)
        do_inject(injector, m)
        return m
    end
end

local EnableForceLoadMod = false
local ModName
function _M.forceEnableLuaMod(en, modname)
    EnableForceLoadMod = en
    ModName = modname
    local pattern = "modindex"
    if EnableForceLoadMod then
        _M.inject_module_text(pattern, function()
            if not KnownModIndex then return end
            local old_ModIndex_UpdateModInfo = KnownModIndex.UpdateModInfo
            function KnownModIndex:UpdateModInfo()
                old_ModIndex_UpdateModInfo(self)
                local modinfo = self.savedata.known_mods[modname]
                if not modinfo then
                    print("[luajit] Mod not found: " .. modname)
                else
                    modinfo.enabled = true
                    print("[luajit] Force enable mod: " .. modname)
                end
            end
        end)
    else
        _M.injectors[pattern] = nil
    end
end

--[[
1. game started
2. game map generated
3. game initialized
]]
local event_idx = 1
function _M.register_event(event_name, callback)
    if not _M[event_name] then
        _M[event_name] = {}
    end
    local new_idx = event_idx
    event_idx = event_idx + 1
    table.insert(_M[event_name], { cb = callback, idx = new_idx })
    return _M[event_name]
end

function _M.unregister_event(event_name, idx)
    if not _M[event_name] then
        return
    end
    for i, v in ipairs(_M[event_name]) do
        if v.idx == idx then
            _M[event_name] = false
            break
        end
    end
end

function _M.push_event(event_name, ...)
    if not _M[event_name] then
        return
    end
    local unregister_list
    for i, v in ipairs(_M[event_name]) do
        if not v then
            goto continue
        end
        local res = xpcall(v.cb, debug.traceback, ...)
        if res == "unregister" then
            unregister_list = unregister_list or {}
            unregister_list[#unregister_list + 1] = v.idx
        end
        ::continue::
    end
    if unregister_list then
        for _, idx in ipairs(unregister_list) do
            _M.unregister_event(event_name, idx)
        end
    end
end

local function register_event_code(event_name, script)
    if not script or type(script) ~= "string" or script == "" then
        return
    end
    _M.register_event(event_name, function()
        local f, err = loadstring(script)
        if f then
            local res = xpcall(f, debug.traceback)
            if res then return res end
        else
            print("[luajit] Error in " .. event_name .. " script: " .. err)
        end
        return "unregister"
    end)
end

function _M.register_event_before_main(script)
    register_event_code("before_main", script)
end

function _M.register_event_game_initialized(script)
    register_event_code("game_initialized", script)
end

function _M.register_event_game_initialized_injector_file(file, args)
    _M.register_event("game_initialized", function()
        if not file or type(file) ~= "string" or file == "" then
            return
        end
        local inject_fp = io.open(file, 'r')
        if not inject_fp then
            error('DontStarveInjector: Cannot open Injector File: ' .. file)
        end
        local fn = loadstring(inject_fp:read '*a')
        inject_fp:close()
        if fn then
            local inject_args = args or {}
            setfenv(fn, setmetatable({ arg = inject_args }, { __index = _G, __newindex = _G }))
            return xpcall(fn, debug.traceback)
        else
            print("[luajit] Error in injector file: " .. file)
        end
    end)
end

function _M.tostring()
    return "GameLuaInjector", inited, "EnableForceLoadMod", EnableForceLoadMod, "ModName", ModName
end
