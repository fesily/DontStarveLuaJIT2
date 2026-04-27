local registry = debug.getregistry()

registry["LJ_DS_slowtailcall_mods"] = {
    ["test-wrapped"] = true,
}

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

local plain = compile_case("@../mods/test-plain/test.lua")
local wrapped = compile_case("@../mods/test-wrapped/test.lua")

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

registry["LJ_DS_slowtailcall_mods"] = nil
