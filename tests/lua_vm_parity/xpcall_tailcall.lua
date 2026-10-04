-- Characterization repro: tail call to a C function (xpcall).
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
-- LuaJIT reuses the frame for every BC_CALLT (vm_x86.dasc:4991, no PCRC split)
-- and books the lost frame through the DS tail-count layer, so this VM prints:
--         <chunk>(1,1)
--         =[C] ?                                    -- C frame, no caller to name it
--         =(tail call) ?                            -- the elided wrapper frame
--         <chunk>(3,1) in main chunk
--
-- This is a known, intentional difference (aligning it means changing
-- BC_CALLT-with-C-callee semantics: interpreter dispatch, lj_crecord/lj_record
-- and frame_tailcalls bookkeeping) - see docs/mac-lua51-parity-audit.md 5.2.
-- The script prints the whole report and pins the current shape, so any change
-- shows up as a failure instead of drifting silently.

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
local c_at = tb:find("        =[C] ?", 1, true)
if not c_at then
  error("expected the unnamed C frame (\"        =[C] ?\") in the report:\n" .. tb, 2)
end
if not tb:find("\n        =(tail call) ?", c_at, true) then
  error("expected the elided caller frame (\"        =(tail call) ?\") right after the C frame:\n" .. tb, 2)
end
if tb:find("in function 'wrapper'", 1, true) then
  error("the caller frame is no longer elided - the C-callee tail call was aligned; "
        .. "update this script and docs/mac-lua51-parity-audit.md 5.2:\n" .. tb, 2)
end

print("ok xpcall_tailcall (characterization: caller frame elided for a C callee, see 5.2)")
