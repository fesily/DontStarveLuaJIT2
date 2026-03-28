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
    return arg[1]
end

assert(test(2, 1) == 2)

local function test_mixed(...)
    local packed = { ... }
    return arg[1], rawget(arg, "n"), packed[1], select("#", ...)
end

do
    local first, argn, packed_first, count = test_mixed(2, 1, nil, 4)
    assert(first == 2)
    assert_compat_argn(argn, 4)
    assert(packed_first == 2)
    assert(count == 4)
end

local function test_select_only(...)
    return select("#", ...)
end

assert(test_select_only() == 0)
assert(test_select_only(2, 1, nil, 4) == 4)

local function count_named_locals(level, target)
    local index = 1
    local count = 0
    while true do
        local name = debug.getlocal(level, index)
        if not name then
            return count
        end
        if name == target then
            count = count + 1
        end
        index = index + 1
    end
end

local function test(...)
    local arg = { ... }
    local function probe()
        assert(count_named_locals(3, "arg") == 2)
    end
    probe()
    return arg[1]
end

assert(test(2, 1) == 2)