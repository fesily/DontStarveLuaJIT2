--[[
    1. Inject lua text into file afterload
    2. Replace lua text
]]
local spdlog = ...

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
    injector.afterload = nil
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
            _M[event_name] = nil
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

local myio = io2 or io
local myenv
local function myloadfile(filename, chunkname)
    spdlog.info("mydofile " .. filename)
    local load = _VERSION == "Lua 5.1" and loadstring or load
    local f = assert(myio.open(filename))
    ---@type string
    local str = f:read "*a"
    f:close()
    if filename:find("launch.lua", 1, true) then
        str = str:gsub('%.source:sub%(2%)', '%.source:sub(1)')
        
        spdlog.info(str)
    end
    local fn, err = load(str, chunkname or filename)
    if fn then
        setfenv(fn, myenv)
    end
    return fn, err
end

local function mydofile(filename, chunkname)
    local fn, err = myloadfile(filename, chunkname or filename)
    if not fn then
        error(err)
    end
    return fn()
end

myenv = setmetatable({io=myio, dofile=mydofile, spdlog=spdlog}, { __index = _G, __newindex = _G })

local function register_event_code(event_name, script)
    if not script or type(script) ~= "string" or script == "" then
        return
    end
    spdlog.info("register_event[script] " .. event_name)
    _M.register_event(event_name, function()
        local f, err = loadstring(script)
        if f then
            spdlog.info("execute_event[script] " .. event_name)
            if event_name == "before_main" then
                setfenv(f, myenv)
            end
            local res = xpcall(f, function (error)
                spdlog.error("[luajit] in " .. event_name .. " script Error :" .. tostring(error) .. "\n" .. debug.traceback())
            end)
            if res then return res end
        else
            spdlog.error("[luajit] Error in " .. event_name .. " script: " .. err)
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

function _M.check_enable_debugger()
    if not TheSim:ShouldInitDebugger() then
        return false
    end
    local debugger = debug.getregistry()["lua-debug"]
    local launchmode = debugger;
    package.preload.debuggee = function()
        Debuggee = { ready = false };
        Debuggee.start = function()
            if Debuggee.ready then return "ok", Debuggee.host, debugger end;
            local host;
            if launchmode then
                spdlog.info("[Lua Debugger] Launch mode detected.");
                host = debugger;
            else
                local path = os.getenv("LUA_DEBUG_CORE_ROOT")
                if not path then
                    error("LUA_DEBUG_CORE_ROOT environment variable not set")
                end
                local filename = path .. "/script/debugger.lua"
                debugger = assert(myloadfile(filename))(filename)

                local port = 12306;
                if not TheNet:IsDedicated() then
                    port = 12306;
                else
                    port = 12307;
                    if TheShard:IsMaster() then
                        port = 12307;
                    elseif TheShard:IsSecondary() then
                        port = 12308;
                    end
                end
                host = { address = "127.0.0.1:" .. port };
                debugger:start(host);
                spdlog.info("[Lua Debugger] Debugger host address: " .. host.address);
            end
            debugger:event("autoUpdate", false);
            Debuggee.host = host.address;
            Debuggee.ready = true;
            return "ok", Debuggee.host, debugger
        end
        Debuggee.poll = function()
            debugger:event "update";
        end
        return Debuggee
    end
    return true
end
