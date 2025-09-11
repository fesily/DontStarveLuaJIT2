local builtin_lua = {
    string.len, math.deg, math.rad, table.foreachi, table.foreach, table.getn, table.remove, table.move
}

local function NoBuiltIn(str)
    print(str)
    assert(type(str) == "string" and str:find("builtin", 1, true) == nil)
end
local check_fns = {
    tostring,
    function(fn)
        return debug.getinfo(fn).short_src
    end,
}
for i, checkfn in ipairs(check_fns) do
    for i, fn in ipairs(builtin_lua) do
        NoBuiltIn(checkfn(fn))
    end
end

for i, fn in ipairs(builtin_lua) do
    local ok = pcall(function() return string.dump(fn) end)
    assert(not ok)
end
---@param info debuginfo
local function check_debug_info(info)
    assert(type(info) == "table")
    assert(info.name == nil)
    assert(info.namewhat == "")
    assert(info.source == '=[C]', info.source)
    assert(info.short_src == '[C]', info.short_src)
    assert(info.linedefined == -1)
    assert(info.lastlinedefined == -1)
    assert(info.what == "C")
    assert(info.currentline == -1)
    assert(info.nups == 0)
    assert(type(info.activelines) == "nil")
    assert(info.func)
end

for i, fn in ipairs(builtin_lua) do
    check_debug_info(debug.getinfo(fn))
end
