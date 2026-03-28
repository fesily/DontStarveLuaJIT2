local has_ffi, ffi = pcall(require, "ffi")
local compat_vararg_n = has_ffi and ffi.abi("compat_vararg_n")

local function assert_compat_argn(value, expected)
    if compat_vararg_n then
        assert(value == expected)
    else
        assert(value == nil)
    end
end

local function test(...)
    local arg = {...}
    arg[1] = 2
    assert(arg[1] == 2)
    assert(rawget(arg, "n") == nil)
    if 1 then
        assert(arg[1] == 2)
        assert(rawget(arg, "n") == nil)
    end
    local limit = true
    while limit do
        assert(arg[1] == 2)
        assert(rawget(arg, "n") == nil)
        limit = false
    end
    do
        assert(arg[1] == 2)
        assert(rawget(arg, "n") == nil)
    end
    repeat
        assert(arg[1] == 2)
        assert(rawget(arg, "n") == nil)
    until true
end
local function test1(...)
    assert(arg[1] == 2)
    assert_compat_argn(rawget(arg, "n"), 1)
    if 1 then
        assert(arg[1] == 2)
        assert_compat_argn(rawget(arg, "n"), 1)
    end
    local limit = true
    while limit do
        assert(arg[1] == 2)
        assert_compat_argn(rawget(arg, "n"), 1)
        limit = false
    end
    do
        assert(arg[1] == 2)
        assert_compat_argn(rawget(arg, "n"), 1)
    end
    repeat
        assert(arg[1] == 2)
        assert_compat_argn(rawget(arg, "n"), 1)
    until true
end
local function test3(a,b,...)
    assert(arg)
    assert_compat_argn(rawget(arg, "n"), select("#", ...))
end
test(1)
test1(2)
test3()
test3(1,2,3)