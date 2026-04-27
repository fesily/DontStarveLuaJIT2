local registry = debug.getregistry()

registry["LJ_DS_slowtailcall_mods"] = {
    ["test-recursion"] = true,
}

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

local fn = assert(loadstring(source, "@../mods/test-recursion/main.lua"))
local ok, result = pcall(fn)

registry["LJ_DS_slowtailcall_mods"] = nil

assert(ok == true)
assert(result == 123)
