-- Regression guard: engine-parity traceback lines for elided tail calls.
--
-- The engine-embedded Lua 5.1 prints one "        =(tail call) ?" line per
-- elided tail call (info_tailcall: what="tail", source="=(tail call)",
-- namewhat="") through db_errorfb.  LuaJIT's patched luaL_traceback used to
-- collapse the same virtual levels into a tab-indented "(...tail calls...)"
-- marker.  Gated by LJ_DS_TRACEBACK_PATCH (luajit/src/lj_arch.h): with that
-- switch off the marker (and the stock "stack traceback:" header) comes back and
-- this test must fail.
--
-- Call shape matters (same as the real mod-load path): a chunk-like function
-- invoked by xpcall, which then calls the tail-call chain with a plain
-- statement.  That layout yields exactly one pseudo frame per elided tail call.

local function fail(msg)
  error(msg, 2)
end

local function tail_error() local t = nil return t.x end     -- error site
local tail_line = debug.getinfo(tail_error, "S").linedefined
local function mid() return tail_error() end                -- tail call (elided)
local function top() return mid() end                       -- tail call (elided)
local function run() top() end                              -- chunk-like caller

local ok, tb = xpcall(run, debug.traceback)
if ok then
  fail("the tail-call fixture was expected to raise")
end
if type(tb) ~= "string" then
  fail("a string-returning traceback handler was expected, got " .. type(tb))
end

-- 1. one engine-shaped pseudo frame per elided tail call
local tail_lines, first_at, last_at = 0, nil, nil
local pos = 1
while true do
  local at = tb:find("\n        =(tail call) ?", pos, true)
  if not at then break end
  tail_lines = tail_lines + 1
  first_at = first_at or at
  last_at = at
  pos = at + 1
end
if tail_lines ~= 2 then
  fail(string.format("expected 2 '        =(tail call) ?' lines, got %d:\n%s", tail_lines, tb))
end

-- 2. the upstream LuaJIT marker must not come back
if tb:find("(...tail calls...)", 1, true) then
  fail("upstream '(...tail calls...)' marker must not appear:\n" .. tb)
end

-- 3. engine header + no "<src:line>" fallback
if not tb:find("LUA ERROR stack traceback:", 1, true) then
  fail("engine traceback header missing:\n" .. tb)
end
if tb:find("in function <", 1, true) then
  fail("the engine has no ' in function <src:line>' fallback:\n" .. tb)
end

-- 4. ordering: innermost real frame, then the elided ones in call order
local inner = tb:find(string.format("tailcall_lines.lua(%d,1)", tail_line), 1, true)
if not inner then
  fail(string.format("innermost frame tailcall_lines.lua(%d,1) missing:\n%s", tail_line, tb))
end
if inner > first_at then
  fail("the innermost frame must be printed before the tail-call frames:\n" .. tb)
end
if first_at > last_at then
  fail("tail-call frames must be printed in call order:\n" .. tb)
end

-- 5. deep chain (past LEVELS1+LEVELS2): the engine compresses the middle with a
-- single "\n\t..." and still prints each surviving level at most once.  The
-- upstream LuaJIT walk (`level = ar.i_ci - TRACEBACK_LEVELS2`) restarted at a
-- negative level once the tail-count layer materialized virtual levels, which
-- re-printed frames and emitted phantom C frames.
local function build_deep(n)
  local src = {"local function deep() local t = nil return t.x end"}
  for i = 1, n do
    src[#src + 1] = string.format("local function f%d() return %s() end",
                                  i, i == 1 and "deep" or ("f" .. (i - 1)))
  end
  src[#src + 1] = string.format("local function run() f%d() end", n)
  src[#src + 1] = "return run"
  return assert(loadstring(table.concat(src, "\n"), "deep_chain"))()
end

local ok3, tb3 = xpcall(build_deep(20), debug.traceback)
if ok3 then
  fail("the deep tail-call fixture was expected to raise")
end
local dots, pseudo3, dup = 0, 0, {}
for line in tb3:gmatch("[^\n]+") do
  if line == "\t..." then
    dots = dots + 1
  elseif line == "        =(tail call) ?" then
    pseudo3 = pseudo3 + 1
  elseif line:find("^        ") or line:find("^%s+[%w%p]") then
    if dup[line] then
      fail("frame line printed twice in one report (compression walk regression): " .. line .. "\n" .. tb3)
    end
    dup[line] = true
  end
end
if dots ~= 1 then
  fail(string.format("expected exactly one '\\t...' compression marker, got %d:\n%s", dots, tb3))
end
-- structural bound: at most LEVELS1 leading + LEVELS2 trailing levels survive
if pseudo3 < 2 or pseudo3 > 22 then
  fail(string.format("tail-call lines out of the compressed-walk bound (got %d):\n%s", pseudo3, tb3))
end
-- and the pre-compression part must stay [deepest frame, pseudo lines...]
-- (the traceback string starts with the error message line, so slice from the
-- header to the marker)
local hdr = tb3:find("LUA ERROR stack traceback:", 1, true)
local cut = tb3:find("\n\t...", hdr, true) or #tb3
local real_before = 0
for line in tb3:sub(hdr, cut):gmatch("[^\n]+") do
  if line ~= "LUA ERROR stack traceback:" and line ~= "        =(tail call) ?" then
    real_before = real_before + 1
  end
end
if real_before ~= 1 then
  fail(string.format("expected 1 real frame before the compression marker, got %d:\n%s", real_before, tb3))
end

print("ok tailcall_lines")
