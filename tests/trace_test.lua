local function trace_print_impl(...)
    print("[trace] ",...)
end

local function create_trace_op_print(op)
    op = '['..op..']'
    return function(...)
        trace_print_impl(op, ...)
    end
end

local trace_print_write = create_trace_op_print("write")
local trace_print_read = create_trace_op_print("read")
local trace_print_call = create_trace_op_print("call")
local trace_print_rawget = create_trace_op_print("rawget")
local trace_print_rawset = create_trace_op_print("rawset")

local get_proxy
---@type metatable
local tracking_mt = {
    __index = function(t, k)
        local val = t._original[k]
        local new_path = t.trace_path .. "." .. k
        trace_print_read(new_path, k, val)
        if type(val) == "table" or type(val) == "function" then
            return get_proxy(val, new_path)
        else
            return val
        end
    end,
    __newindex = function(t, k, v)
        local new_path = t.trace_path .. "." .. k
        trace_print_write(new_path, k, v)
        if type(v) == "table" or type(v) == "function" then
            v = get_proxy(v, new_path)
        end
        t._original[k] = v
    end,
    __call = function(t, ...)
        trace_print_call(t.trace_path, ...)
        return t._original(...)
    end
}

local proxy_cache = setmetatable({}, { __mode = "v" })


get_proxy = function(original, path)
    if proxy_cache[original] then
        return proxy_cache[original]
    else
        local proxy = setmetatable({ _original = original , trace_path = path}, tracking_mt)
        proxy_cache[original] = proxy
        return proxy
    end
end


GLOBAL = _G
_G.env = _G

local env = {
    GLOBAL = _G,
    modimport = function ()
        print("modimport")
        assert(false)
    end
}
env.env = env


-- local env = get_proxy(_G, "_G")
 
-- local original_rawget = rawget
-- local original_rawset = rawset

-- original_rawset(env, "rawget", function(t, k)
--     trace_print_rawget(tostring(t.trace_path or "unknown") ,tostring(k))
--     return original_rawget(t, k)
-- end)
-- original_rawset(env , "rawset",  function(t, k, v)
--     trace_print_rawset(tostring(t.trace_path or "unknown"), tostring(k), tostring(v))
--     return original_rawset(t, k, v)
-- end)

local buf = assert(loadfile([[tests\sect\fengxuemy.lua]]))
local old_open = io.open
function io.open(filename, mod)
    if filename:find("modmain.lua", 1, true) then
        filename = [[C:\Program Files (x86)\Steam\steamapps\workshop\content\322330\3288149713\modmain1.lua]]
    elseif filename:find("modmain0.lua", 1, true) then
        filename = [[C:\Program Files (x86)\Steam\steamapps\workshop\content\322330\3288149713\modmain0.lua]]
    end
    return old_open(filename, mod)
end
local old_loadfile = loadfile
function loadfile(filename, mode, env)
    print (filename)
    if filename:find("modmain.lua", 1, true) then
        filename = "tests/mods/workshop-123/modmain12.lua"
    elseif filename:find("modmain0.lua", 1, true) then
        filename = "tests/mods/workshop-123/modmain0.lua"
    end
    return old_loadfile(filename, mode, env)
end
local old_debug_sethook = debug.sethook
function debug.sethook(...)
    
end

local old_debug_getinfo = debug.getinfo
local old_load_string = loadstring

function debug.getinfo(thread, f, what)
    local rest = old_debug_getinfo(thread, f, what)
    if thread == loadstring then
        rest = old_debug_getinfo(old_load_string, f, what)
    end
    return rest
end

function LoadPrefabFile( filename, async_batch_validation, search_asset_first_path )
    assert(false)
end

function os.time(...)
    return 1234567890
end
function loadstring(text, filename)
    print ("loadstring", filename)
    print (text)
    old_open("1.lua","w"):write(text):close()
    return old_load_string(text, filename)
end


MODROOT = "../mods/workshop-123/"
setfenv(buf, env)
pcall(buf)

-- local bytecodes = assert(assert(string.dump(buf)) )

-- local proto = vm.bc_to_state(bytecodes)

-- local func = vm.wrap_state(proto,  env)
-- func()