-- Regression guard: engine-parity naming for metamethod frames.
--
-- The engine-embedded Lua 5.1 names only frames pushed by OP_CALL/OP_TAILCALL/
-- OP_TFORLOOP (ldebug.c getfuncname), so a frame entered through a metamethod
-- keeps namewhat == "" and db_errorfb prints no " in function '...'" suffix.
-- LuaJIT's lj_debug_funcname() reports "metamethod" + the event name for those
-- frames, which used to leak into debug.getinfo() and debug.traceback() as
-- namewhat="metamethod" / " in function '__index'".
-- Gated by LJ_DS_DEBUG_FUNCNAME_PATCH (luajit/src/lj_arch.h): with that switch
-- off this test must fail.
--
-- Positive control: frames pushed by a normal call keep their name.

local function fail(msg)
  error(msg, 2)
end

local meta_namewhat, meta_name
-- one-liner: the frame's reported line == the error line == linedefined, so the
-- assertion needle below is stable without hard-coded line numbers
local function boom() local i = debug.getinfo(1, "n") meta_namewhat, meta_name = i.namewhat, i.name local t = nil return t.x end

local obj = setmetatable({}, { __index = boom })
local boom_line = debug.getinfo(boom, "S").linedefined

local ok, tb = xpcall(function() return obj.missing end, debug.traceback)
if ok then
  fail("the __index metamethod was expected to raise")
end
if type(tb) ~= "string" then
  fail("a string-returning traceback handler was expected, got " .. type(tb))
end

-- 1. debug.getinfo() must not name the metamethod frame
if meta_namewhat ~= "" then
  fail("metamethod frame namewhat must be empty (engine parity), got: " .. tostring(meta_namewhat))
end
if not (meta_name == nil or meta_name == "") then
  fail("metamethod frame name must be empty (engine parity), got: " .. tostring(meta_name))
end

-- 2. the printed frame line keeps the engine shape and carries no suffix
local needle = string.format("metamethod_name.lua(%d,1)", boom_line)
local at = tb:find(needle, 1, true)
if not at then
  fail("engine-shaped frame line " .. needle .. " missing from traceback:\n" .. tb)
end
local eol = tb:find("\n", at, true) or (#tb + 1)
local frame_line = tb:sub(at, eol - 1)
if frame_line:find("in function", 1, true) then
  fail("metamethod frame must stay unnamed, got: " .. frame_line .. "\n" .. tb)
end

-- 3. no metamethod event name may leak into the traceback text
for _, leaked in ipairs({ "'__index'", "'__newindex'", "'__call'", "in function 'metamethod'" }) do
  if tb:find(leaked, 1, true) then
    fail("leaked metamethod name " .. leaked .. ":\n" .. tb)
  end
end

-- 4. positive control: a frame pushed by a normal Lua call keeps its name
local named_line
-- one-liner for the same stable-needle reason as above
local function named() named_line = debug.getinfo(1, "S").linedefined local t = nil return t.x end
-- must be a plain (non-tail) call from Lua: xpcall/return would drop the name
local function caller() local r = named() return r end
local ok2, tb2 = xpcall(caller, debug.traceback)
if ok2 then
  fail("the named fixture was expected to raise")
end
local named_needle = string.format("metamethod_name.lua(%d,1)", named_line)
local named_at = tb2:find(named_needle, 1, true)
if not named_at then
  fail("engine-shaped frame line for the named fixture missing:\n" .. tb2)
end
if not tb2:find("in function 'named'", 1, true) then
  fail("named frames must keep their name (positive control):\n" .. tb2)
end
local named_eol = tb2:find("\n", named_at, true) or (#tb2 + 1)
if not tb2:sub(named_at, named_eol - 1):find("in function 'named'", 1, true) then
  fail("the name must be attached to the named frame itself:\n" .. tb2)
end

print("ok metamethod_name")
