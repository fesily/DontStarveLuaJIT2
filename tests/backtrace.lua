local registry = debug.getregistry()
local callback_calls = {}

registry["LJ_DS_dynamic_tailcall_cb"] = function(reader, data, chunkname, mode)
    callback_calls[#callback_calls + 1] = {
        chunkname = chunkname,
        mode = mode,
    }
    return chunkname == "@dynamic_tailcall_wrapped.lua"
end

local function compile_case(chunkname)
    local source = [[
local function leaf()
    return {
        level1 = debug.getinfo(1, "nSlt"),
        level2 = debug.getinfo(2, "nSlt"),
        traceback = debug.traceback(),
    }
end

local function bounce()
    return leaf()
end

local result = bounce()
return result
]]

    return assert(loadstring(source, chunkname))()
end

local plain = compile_case("@dynamic_tailcall_plain.lua")
local wrapped = compile_case("@dynamic_tailcall_wrapped.lua")

assert(#callback_calls == 2)
assert(callback_calls[1].chunkname == "@dynamic_tailcall_plain.lua")
assert(callback_calls[2].chunkname == "@dynamic_tailcall_wrapped.lua")

assert(plain.level1.what == "Lua")
assert(plain.level1.istailcall == false)
assert(plain.level2.what == "main")
assert(plain.level2.istailcall == false)
assert(not plain.traceback:find("(tail call):?", 1, true))

assert(wrapped.level1.what == "Lua")
assert(wrapped.level1.istailcall == false)
assert(wrapped.level2.istailcall == true)
assert(wrapped.level2.what == "tail")
assert(wrapped.level2.short_src == "(tail call)")
assert(wrapped.traceback:find("(tail call): ?", 1, true))
assert(not wrapped.traceback:find("LJ_DS_tailcall", 1, true))
assert(not wrapped.traceback:find("___tailcall", 1, true))

registry["LJ_DS_dynamic_tailcall_cb"] = nil
