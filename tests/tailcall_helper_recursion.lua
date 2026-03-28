local registry = debug.getregistry()
local callback_count = 0

registry["LJ_DS_dynamic_tailcall_cb"] = function(reader, data, chunkname, mode)
    callback_count = callback_count + 1
    return chunkname == "@dynamic_tailcall_helper_recursion.lua"
end

local source = [[
local function leaf()
    return 123
end

local function bounce()
    return leaf()
end

local result = bounce()
return result
]]

local fn = assert(loadstring(source, "@dynamic_tailcall_helper_recursion.lua"))
local ok, result = pcall(fn)

registry["LJ_DS_dynamic_tailcall_cb"] = nil

assert(callback_count == 1)
assert(ok == true)
assert(result == 123)