local function test(...)
    return arg[1]
end

assert(test(2, 1) == 2)

local function test(...)
    local arg = { ... }
    return arg[1]
end

assert(test(2, 1) == 2)
