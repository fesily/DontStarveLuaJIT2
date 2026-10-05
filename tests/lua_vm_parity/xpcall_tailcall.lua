-- Engine-parity repro: tail call to a C function (xpcall).
--
-- DST's mod loader does exactly this in scripts/util.lua:786-789:
--     function RunInEnvironment(fn, fnenv)
--         setfenv(fn, fnenv)
--         return xpcall(fn, debug.traceback)   -- tail call to a C function
--     end
-- so every failing modmain goes through it.
--
-- The engine-embedded Lua 5.1 keeps the caller frame for a C callee
-- (lvm.c OP_TAILCALL: PCRLUA elides the frame, PCRC calls normally), hence on a
-- modmain error the engine prints (measured, lua_vm_type=game):
--         <chunk>(4,1)                              -- the error site
--         =[C] in function 'xpcall'
--         <chunk>(5,1) in function 'wrapper'        -- caller frame, named
--         <chunk>(6,1) in main chunk
-- This VM now prints the same (LUA_COMPAT_TAILCALL_CFRAME, luajit/src/lj_arch.h):
-- BC_CALLT splits on the callee's ffid, a C/FF callee runs as a normal call and
-- the parser-appended BC_RETM forwards its results, so the frame survives and
-- the C frame is named from the tail-call site:
--         <chunk>(30,1)
--         =[C] in function 'xpcall'
--         <chunk>(31,1) in function 'wrapper'
--         <chunk>(33,1) in main chunk
--         =[C] ?
-- The script prints the whole report and pins this shape, so a regression that
-- re-elides the caller frame shows up as a failure instead of drifting
-- silently.  See docs/mac-lua51-parity-audit.md 5.2.

local function boom() local t = nil return t.x end
local function wrapper() return xpcall(boom, debug.traceback) end

local ok, tb = wrapper()
assert(ok == false, "the fixture must raise")
assert(type(tb) == "string", "a string-returning traceback handler was expected")

-- full report: diff it against the engine lines quoted in the header
print(tb)

if not tb:find("LUA ERROR stack traceback:", 1, true) then
  error("engine traceback header missing:\n" .. tb, 2)
end
local c_at = tb:find("        =[C] in function 'xpcall'", 1, true)
if not c_at then
  error("expected the named xpcall C frame (\"        =[C] in function 'xpcall'\"):\n" .. tb, 2)
end
local w_at = tb:find("in function 'wrapper'", 1, true)
if not w_at or w_at < c_at then
  error("expected the caller frame (\"in function 'wrapper'\") after the xpcall frame:\n" .. tb, 2)
end
if tb:find("(tail call)", 1, true) then
  error("a C callee must not report an elided frame:\n" .. tb, 2)
end

print("ok xpcall_tailcall (C callee keeps the caller frame, see docs/mac-lua51-parity-audit.md 5.2)")
