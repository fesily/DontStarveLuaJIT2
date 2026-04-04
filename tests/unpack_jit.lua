local has_jit, jit = pcall(require, "jit")
if not has_jit then
  return
end

local has_ffi, ffi = pcall(require, "ffi")
if has_ffi then
  local unpack_patch = ffi.abi("unpack_patch")
  assert(type(unpack_patch) == "boolean")
  if not unpack_patch then
    return
  end
end

local has_opt, jit_opt = pcall(require, "jit.opt")
local has_util, jit_util = pcall(require, "jit.util")

jit.flush()
jit.on()
if has_opt then
  jit_opt.start("hotloop=1")
end

local function foo(...)
  return {...}
end

jit.on(foo, true)

local function drive_trace()
  local last
  for _ = 1, 64 do
    last = foo(1, 2, 3, nil, 5)
  end
  return last
end

local t1 = drive_trace()
assert(t1[5] == 5)
assert(select(5, unpack(t1)) == 5)
assert(rawget(t1, "n") == nil)
assert(#t1 == 5)

local t2 = drive_trace()
assert(t2[5] == 5)
assert(select(5, unpack(t2)) == 5)
assert(rawget(t2, "n") == nil)
assert(#t2 == 5)

if has_util then
  assert(jit_util.traceinfo(1) ~= nil)
end