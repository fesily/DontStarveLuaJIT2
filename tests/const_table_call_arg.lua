local has_ffi, ffi = pcall(require, "ffi")
if has_ffi then
  local big_upval_patch = ffi.abi("big_upval_patch")
  assert(type(big_upval_patch) == "boolean")
  if not big_upval_patch then
    return
  end
end

local function passthrough(arg)
  return arg
end

local direct = passthrough({ 1, 2, 3 })
assert(type(direct) == "table")
assert(direct[1] == 1)
assert(direct[2] == 2)
assert(direct[3] == 3)

local wrapped = { passthrough({ 1, 2, 3 }) }
assert(type(wrapped[1]) == "table")
assert(wrapped[1][1] == 1)
assert(wrapped[1][2] == 2)
assert(wrapped[1][3] == 3)

wrapped[1][1] = 99
assert(direct[1] == 1)

local function argc(...)
  local n = select("#", ...)
  local arg = ...
  assert(n == 1)
  assert(type(arg) == "table")
  assert(arg[1] == 1)
  assert(arg[2] == 2)
  assert(arg[3] == 3)
  return n
end

assert(argc({ 1, 2, 3 }) == 1)

local outer = { argc({ 1, 2, 3 }) }
assert(outer[1] == 1)
assert(outer[2] == nil)