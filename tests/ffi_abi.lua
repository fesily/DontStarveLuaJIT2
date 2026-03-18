local ffi = require("ffi")

local compat_vararg_n = ffi.abi("compat_vararg_n")
local big_upval_patch = ffi.abi("big_upval_patch")
local unpack_patch = ffi.abi("unpack_patch")

assert(type(compat_vararg_n) == "boolean")
assert(type(big_upval_patch) == "boolean")
assert(type(unpack_patch) == "boolean")
assert(ffi.abi("le") or ffi.abi("be"))

local function inspect(...)
    return rawget(arg, "n"), select("#", ...)
end

local argn, count = inspect("alpha", nil, "omega")

if compat_vararg_n then
    assert(argn == count)
else
    assert(argn == nil)
end
