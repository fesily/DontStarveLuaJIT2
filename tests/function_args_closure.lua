local has_ffi, ffi = pcall(require, "ffi")
local compat_vararg_n = has_ffi and ffi.abi("compat_vararg_n")

local function assert_compat_argn(value, expected)
    if compat_vararg_n then
        assert(value == expected)
    else
        assert(value == nil)
    end
end

local function make_counter(...)
    return function(index)
        return arg[index], rawget(arg, "n")
    end
end

do
    local closure = make_counter(10, nil, 30, nil)
    local second, count = closure(2)
    assert(second == nil)
    assert_compat_argn(count, 4)
end

local function outer(...)
    local outer_arg = arg
    local function inner(...)
        return outer_arg[1], rawget(outer_arg, "n"), arg[1], rawget(arg, "n")
    end
    return inner("inner", nil, 7)
end

do
    local outer_first, outer_count, inner_first, inner_count = outer("outer", nil, 5)
    assert(outer_first == "outer")
    assert_compat_argn(outer_count, 3)
    assert(inner_first == "inner")
    assert_compat_argn(inner_count, 3)
end

local function trailing_nil(...)
    return arg[1], arg[2], arg[3], arg[4], rawget(arg, "n"), select("#", ...)
end

do
    local v1, v2, v3, v4, argn, count = trailing_nil(nil, 2, nil, nil)
    assert(v1 == nil)
    assert(v2 == 2)
    assert(v3 == nil)
    assert(v4 == nil)
    assert_compat_argn(argn, 4)
    assert(count == 4)
end