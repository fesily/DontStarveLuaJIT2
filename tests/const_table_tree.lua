local has_ffi, ffi = pcall(require, "ffi")
if has_ffi then
  local big_upval_patch = ffi.abi("big_upval_patch")
  assert(type(big_upval_patch) == "boolean")
  if not big_upval_patch then
    return
  end
end

local function build_tree()
  return {
    list = {
      { value = 1 },
      { value = 2 },
      { value = nil, nested = { "a", nil, "c" } },
    },
    map = {
      alpha = { x = 10, y = { 20, 30 } },
      beta = false,
      gamma = nil,
    },
  }
end

local first = build_tree()
local second = build_tree()

assert(first ~= second)
assert(first.list ~= second.list)
assert(first.list[1] ~= second.list[1])
assert(first.list[3] ~= second.list[3])
assert(first.list[3].nested ~= second.list[3].nested)
assert(first.map ~= second.map)
assert(first.map.alpha ~= second.map.alpha)
assert(first.map.alpha.y ~= second.map.alpha.y)

assert(first.list[3].nested[1] == "a")
assert(first.list[3].nested[2] == nil)
assert(first.list[3].nested[3] == "c")
assert(rawget(first.map, "gamma") == nil)

first.list[1].value = 99
first.list[3].nested[1] = "changed"
first.map.alpha.y[1] = -1

assert(second.list[1].value == 1)
assert(second.list[3].nested[1] == "a")
assert(second.map.alpha.y[1] == 20)

local dumped = string.dump(build_tree)
local restored = assert(loadstring(dumped))
local dumped_tree = restored()

assert(dumped_tree.list[2].value == 2)
assert(dumped_tree.list[3].nested[3] == "c")
assert(dumped_tree.map.alpha.y[2] == 30)
assert(rawget(dumped_tree.map, "gamma") == nil)

dumped_tree.list[2].value = 123
assert(restored().list[2].value == 2)

local function build_large_factory_source(count)
  local parts = { "return function() return {\n" }
  for i = 1, count do
    parts[#parts + 1] = string.format(
      "[%d] = { tag = %d, pair = { %d, %d }, nested = { 'x', nil, { %d } } },\n",
      i,
      i,
      i,
      i + 1,
      i
    )
  end
  parts[#parts + 1] = "} end"
  return table.concat(parts)
end

local large_factory = assert(loadstring(build_large_factory_source(2048)))()
local large_first = large_factory()
local large_second = large_factory()

assert(large_first ~= large_second)
assert(large_first[1024] ~= large_second[1024])
assert(large_first[1024].pair ~= large_second[1024].pair)
assert(large_first[1024].nested ~= large_second[1024].nested)
assert(large_first[1024].nested[2] == nil)
assert(large_first[1024].nested[3] ~= large_second[1024].nested[3])
assert(large_first[1024].nested[3][1] == 1024)

large_first[1024].pair[1] = -1
large_first[1024].nested[3][1] = -2

assert(large_second[1024].pair[1] == 1024)
assert(large_second[1024].nested[3][1] == 1024)

local dumped_large_factory = assert(loadstring(string.dump(large_factory)))
local dumped_large_tree = dumped_large_factory()

assert(dumped_large_tree[2048].tag == 2048)
assert(dumped_large_tree[2048].pair[2] == 2049)
assert(dumped_large_tree[2048].nested[2] == nil)
assert(dumped_large_tree[2048].nested[3][1] == 2048)

local function build_large_hash_factory_source(count)
  local parts = { "return function() return {\n" }
  for i = 1, count do
    parts[#parts + 1] = string.format(
      "k%d = { value = %d, flags = { enabled = false, marker = nil }, branch = { left = { %d }, right = { %d, nil } } },\n",
      i,
      i,
      i,
      i + 10
    )
  end
  parts[#parts + 1] = "} end"
  return table.concat(parts)
end

local large_hash_factory = assert(loadstring(build_large_hash_factory_source(1536)))()
local hash_first = large_hash_factory()
local hash_second = large_hash_factory()

assert(hash_first ~= hash_second)
assert(hash_first.k777 ~= hash_second.k777)
assert(hash_first.k777.flags ~= hash_second.k777.flags)
assert(hash_first.k777.branch ~= hash_second.k777.branch)
assert(hash_first.k777.branch.left ~= hash_second.k777.branch.left)
assert(hash_first.k777.branch.right ~= hash_second.k777.branch.right)
assert(rawget(hash_first.k777.flags, "marker") == nil)
assert(hash_first.k777.branch.right[2] == nil)

hash_first.k777.flags.enabled = true
hash_first.k777.branch.left[1] = -7
hash_first.k777.branch.right[1] = -8

assert(hash_second.k777.flags.enabled == false)
assert(hash_second.k777.branch.left[1] == 777)
assert(hash_second.k777.branch.right[1] == 787)

local dumped_hash_factory = assert(loadstring(string.dump(large_hash_factory)))
local dumped_hash_tree = dumped_hash_factory()

assert(dumped_hash_tree.k1536.value == 1536)
assert(dumped_hash_tree.k1536.flags.enabled == false)
assert(rawget(dumped_hash_tree.k1536.flags, "marker") == nil)
assert(dumped_hash_tree.k1536.branch.left[1] == 1536)
assert(dumped_hash_tree.k1536.branch.right[1] == 1546)
assert(dumped_hash_tree.k1536.branch.right[2] == nil)