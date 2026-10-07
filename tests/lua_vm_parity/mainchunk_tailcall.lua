--[[
  Repro: Lua 5.1 "tail" levels for a C-called frame reused by a top-level
  tail call (main chunk / modmain-style chunk).

  5.1 semantics (engine + lua5.1): a chunk is invoked from C, so its frame
  owns the C caller's return marker, and `return f(...)` at the chunk's top
  level still counts as one lost tail call per elided frame.  debug.getinfo()
  therefore reports one virtual level per elision:
      what == "tail", func == nil, short_src == "=(tail call)"

  This VM: BC_CALLT increments the 5.1 tail-count side array at the reused
  frame slot (BASE-1) -- but lj_debug_frame() only read it for PC-typed Lua
  frames, so a chain whose caller is C silently dropped every such level and
  shifted all outer level numbers up by one per elision (the DST protected-mod
  shell walks levels by absolute number and then loads an empty stub).
  Fixed by debug_isluaframe() in lj_debug.c: it also accepts the C-family
  markers (FRAME_C / FRAME_CP / FRAME_PCALL) whose function slot holds a Lua
  function.  Details: doc/tailcall-level-parity.md.

  Structure note: the chunk's own frame is only elided by a top-level
  `return f(...)`, so the checks must run inside the walker -- nothing after
  the chunk's `return` executes.  A failed check raises, which is what makes
  the process exit non-zero (the host pcall reports it).

  Run:
    src/luajit test/compat51/mainchunk_tailcall.lua   # PASS after the fix
    lua5.1     test/compat51/mainchunk_tailcall.lua   # PASS (reference shape)
]]

io.stdout:setvbuf("no")

local failed = 0

local function expect(name, cond, detail)
  if cond then
    print("PASS  " .. name)
  else
    failed = failed + 1
    print("FAIL  " .. name)
    if detail and detail ~= "" then print("      " .. detail) end
  end
end

-- Expected shape per probed call site (see also tailcall_debug.lua):
--   control: normal call chain, only the helper's frame is elided (1 tail level)
--   main:    the chunk tail-calls the helper, so helper + chunk frames are
--            elided (2 tail levels) and no "main" level is left
local EXPECT = {
  control = { tails = 1, chunk_visible = true },
  main    = { tails = 2, chunk_visible = false },
}

local function scan(tag)
  local tails, top = 0, nil
  for lvl = 1, 64 do
    local i = debug.getinfo(lvl, "S")
    if not i then break end
    if i.what == "tail" then
      tails = tails + 1
      expect(tag .. ": tail level " .. lvl .. " has func==nil", i.func == nil)
    elseif i.what == "main" then
      top = lvl
    end
  end

  local want = EXPECT[tag]
  expect(tag .. ": ntail==" .. want.tails, tails == want.tails, "ntail=" .. tails)
  if want.chunk_visible then
    expect(tag .. ": main-chunk frame still visible", top ~= nil)
  else
    expect(tag .. ": main-chunk frame elided (no main level)", top == nil,
           "main level " .. tostring(top))
  end

  if failed > 0 then
    error("mainchunk_tailcall: " .. failed .. " check(s) failed", 0)
  end
  return tails, top
end

local function helper(tag) return scan(tag) end   -- helper tail-calls scan

-- Control: chunk -> control -> helper, helper tail-calls scan (its frame is
-- elided); passes on both 5.1 and this VM.
do
  local function control() local r = helper("control") return r end
  control()
end

-- Main case: the chunk TAIL-calls the helper at its top level, so both the
-- helper's frame and the chunk's own frame are elided (2 "tail" levels).
return helper("main")
