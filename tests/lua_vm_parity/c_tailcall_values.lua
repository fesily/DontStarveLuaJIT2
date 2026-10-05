-- C-callee tail calls (LUA_COMPAT_TAILCALL_CFRAME, luajit/src/lj_arch.h): the
-- caller frame survives and the C/fast function's results are forwarded
-- unchanged (0..N values), ditto the engine-embedded Lua 5.1 (OP_TAILCALL PCRC
-- calls the C callee normally, src/lua51/src/lvm.c:611-636).
--
-- BC_CALLT splits on the callee's ffid: Lua callees still elide the frame
-- (still one "        =(tail call) ?" line per elided frame in a traceback),
-- C/FF callees run as a normal call and the parser-appended BC_RETM forwards
-- their results to the caller's caller.  The interpreter and the JIT recorder
-- must agree, so the shapes are checked with the JIT off and on.
--
-- Gated by LUA_COMPAT_TAILCALL_CFRAME ("-DLUA_COMPAT_TAILCALL_CFRAME=0", or a
-- backend without the split — x64 without GC64, x86, arm — restores the stock
-- behavior): with it off this test must fail on "the caller frame must survive
-- a C tail call" and xpcall_tailcall.lua passes again.
--
-- KNOWN (pre-existing, unrelated to this switch): the arenagc variant
-- (luajit-arenagc.exe / lua51DS_gengc.dll) dies with exit 5 while looping the
-- traceback/metamethod shape below; it reproduces with the switch off, so run
-- this file against the default variant only.

local function n(...) return select('#', ...) end

-- Result forwarding: the C/FF callee's exact result count reaches the caller.
-- Runs once with the JIT off and hot (200x) with the JIT on, so a JIT-only
-- count/order/nil-fill regression cannot pass this file.
local big300 = {}
for i = 1, 300 do big300[i] = i end
local function vtail(...) return select(2, ...) end          -- vararg caller (BC_CALLMT)
local function lvarg(...) return ... end                     -- vararg Lua callee
local function check_values(tag)
  local function t0() return unpack({}) end
  local function t3() return unpack({ 1, 2, 3 }) end
  assert(n(t0()) == 0, tag .. ": 0 results must stay 0")
  assert(n(t3()) == 3, tag .. ": 3 results must stay 3")
  local a, b, c = t3()
  assert(a == 1 and b == 2 and c == 3, tag .. ": 3-result values must survive")
  -- pcall() returns true + the callee's results: 1 value for a 0-result
  -- function, 2 for a one-result function.
  local function t1() return pcall(function() end) end
  local function t2() return pcall(function() return 7 end) end
  assert(n(t1()) == 1, tag .. ": pcall over a 0-result function must return 1 value")
  local ok1, v1 = t1()
  assert(ok1 == true and v1 == nil, tag .. ": the pcall result must be forwarded")
  assert(n(t2()) == 2, tag .. ": 2 results must stay 2")
  local ok2, v2 = t2()
  assert(ok2 == true and v2 == 7, tag .. ": both pcall results must be forwarded")
  -- Vararg caller: the C/FF tail call is a BC_CALLMT, so MULTRES feeds the
  -- appended RETM; the Lua vararg callee keeps the stock eliding path.
  assert(n(vtail(1, "x", nil, 3)) == 3, tag .. ": vararg caller must forward 3")
  local vx, vy, vz = vtail(1, "x", nil, 3)
  assert(vx == "x" and vy == nil and vz == 3, tag .. ": vararg values must survive")
  assert(n(vtail(1)) == 0, tag .. ": vararg caller with no extras must forward 0")
  assert(n(lvarg(1, nil, 3)) == 3, tag .. ": vararg Lua callee must forward 3")
  -- More than 255 results: MULTRES is full width, so no byte-width truncation.
  local function t300() return unpack(big300, 1, 300) end
  assert(n(t300()) == 300, tag .. ": 300 results must stay 300")
  local r1, r2, r3
  r1, r2, r3 = t300()
  assert(r1 == 1 and r2 == 2 and r3 == 3, tag .. ": first results must survive")
  local r300 = select(300, t300())
  assert(r300 == 300, tag .. ": the 300th result must survive")
  -- Extra destinations are nil-filled, extras are discarded.
  local x1, x2, x3, x4 = t3()
  assert(x1 == 1 and x2 == 2 and x3 == 3 and x4 == nil, tag .. ": nil fill")
end

jit.off(); check_values("interp")
jit.on()
for i = 1, 200 do check_values("jit") end
jit.off()
do
  local ji = require("jit.util")
  local ntr = 0
  for i = 1, 100000 do if not ji.traceinfo(i) then break end; ntr = ntr + 1 end
  assert(ntr > 0, "the heated result-forwarding loop must compile at least one trace")
end

-- Traceback shape: the C frame is named from the tail-call site and the caller
-- frame survives.  `pcall(f, handler)` is *not* a message-handler form (only
-- xpcall takes one), so the shapes are anchored on xpcall and on an error
-- raised inside a tail-called pcall (bad argument: no function).
local function check_shape(tag)
  local function boom() local t = nil return t.x end
  local function wrap() return xpcall(boom, debug.traceback) end
  local function run() local ok, tb = wrap() return ok, tb end
  local ok, tb = run()
  assert(ok == false and type(tb) == "string", tag .. ": fixture must raise")
  if not tb:find("LUA ERROR stack traceback:", 1, true) then
    error(tag .. ": engine traceback header missing:\n" .. tb, 2)
  end
  local w_at = tb:find("in function 'wrap'", 1, true)
  if not w_at then
    error(tag .. ": the caller frame must survive a C tail call:\n" .. tb, 2)
  end
  local c_at = tb:find("        =[C] in function 'xpcall'", 1, true)
  if not c_at then
    error(tag .. ": expected the named xpcall C frame:\n" .. tb, 2)
  end
  if w_at < c_at then
    error(tag .. ": the caller frame must be reported after the xpcall frame:\n" .. tb, 2)
  end
  if not tb:find("in function 'run'", 1, true) then
    error(tag .. ": the caller's caller frame must survive a C tail call:\n" .. tb, 2)
  end
  if tb:find("(tail call)", 1, true) then
    error(tag .. ": no elided frame may be reported for a C callee:\n" .. tb, 2)
  end

  -- Same for an error raised inside a tail-called pcall.
  local function pwrap() return pcall() end
  local pok, ptb = xpcall(function() local r = pwrap() return r end, debug.traceback)
  assert(pok == false and type(ptb) == "string", tag .. ": pcall fixture must raise")
  if not ptb:find("in function 'pwrap'", 1, true) then
    error(tag .. ": the caller frame must survive a C tail call (pcall):\n" .. ptb, 2)
  end
  if not ptb:find("        =[C] in function 'pcall'", 1, true) then
    error(tag .. ": expected the named pcall C frame:\n" .. ptb, 2)
  end
  if ptb:find("(tail call)", 1, true) then
    error(tag .. ": no elided frame may be reported for a C callee (pcall):\n" .. ptb, 2)
  end

  -- FF fallback tail-calling a metamethod (FFH_TAILCALL) that is resolved
  -- through __call: the metamethod replaces the fast function's frame and the
  -- caller frame still survives.  Guards the KBASE restore on the C-frame path:
  -- vmeta_call uses KBASE==BASE as its "coming from a CALLT" flag, so a stale
  -- KBASE would silently elide the caller frame again (layout-dependent).
  local function site(self) local t = nil return t.x end
  local mt = setmetatable({}, { __call = site })
  local function tstring() return tostring(setmetatable({}, { __tostring = mt })) end
  local tstring_line = debug.getinfo(tstring, "S").linedefined
  local sok, stb = xpcall(tstring, debug.traceback)
  assert(sok == false and type(stb) == "string", tag .. ": __call fixture must raise")
  local nm = stb:find("in function 'tostring'", 1, true)
  if not nm then
    error(tag .. ": the metamethod frame must be named from the tail-call site:\n" .. stb, 2)
  end
  local cl = stb:find(string.format("(%d,1)", tstring_line), 1, true)
  if not cl or cl < nm then
    error(tag .. ": the caller frame must survive an FF fallback tail call:\n" .. stb, 2)
  end
  if stb:find("(tail call)", 1, true) then
    error(tag .. ": no elided frame may be reported (FF __call case):\n" .. stb, 2)
  end
end

jit.off(); check_shape("interp")
-- Make the C-callee tail-call path hot so the recorder compiles it too.
jit.on()
for i = 1, 200 do check_shape("jit") end
jit.off()

-- Lua tail calls still elide: constant stack.
local function loop(k) if k == 0 then return 0 end return loop(k-1) end
assert(loop(200000) == 0, "Lua tail recursion must not grow the stack")

-- Bytecode format boundary.  The trailing BC_RETM is part of the bytecode, so
-- a pre-change dump (stock CALLT with nothing behind it) would make the C
-- return resume past the prototype; lj_bcdump.h therefore bumps BCDUMP_VERSION
-- to 0x80 (stock is 2) while this switch is on, and such chunks must be
-- rejected at load time instead of running off the prototype.  A chunk
-- claiming the stock version stands in for them here.
local function dumped(x) return math.abs(x) end
local blob = string.dump(dumped)
assert(blob:byte(1) == 0x1b and blob:byte(2) == 0x4c and blob:byte(3) == 0x4a,
       "unexpected dump header")
assert(blob:byte(4) == 0x80, "the dump version must be 0x80 with this switch on")
local fresh, ferr = loadstring(blob)
assert(fresh ~= nil, "a dump of this VM must still load: " .. tostring(ferr))
assert(fresh(-7) == 7, "the reloaded dump must still run the C-callee tail call")
local stock = blob:sub(1, 3) .. string.char(2) .. blob:sub(5)
local bad, berr = loadstring(stock)
if bad ~= nil then
  error("a pre-change dump version must be rejected: the bytecode format changed")
end
if type(berr) ~= "string" or not berr:find("incompatible bytecode", 1, true) then
  error("rejecting a pre-change dump must report an incompatible bytecode, got: "
        .. tostring(berr))
end

print("ok c_tailcall_values")
