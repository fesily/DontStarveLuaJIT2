local existing_arg = rawget(_G, "arg")

assert(arg == existing_arg)

local function passthrough(...)
    return select("#", ...)
end

assert(passthrough() == 0)
assert(passthrough(1, 2, nil, 4) == 4)