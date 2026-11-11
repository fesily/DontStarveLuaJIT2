---
name: luajit-int3-hook-context-verification
description: "LuaJIT int3 fork: verify/relax which luaJIT_int3_* calls a Lua debug hook may make — C hook probe, delivery order (trap before line hook), teeth by reverting the predicate, hard-context BUSY, and the MinGW XCFLAGS stale-object trap"
---

# When to use

Changing which contexts may call `luaJIT_int3_*` (e.g. allowing `start`/`cancel`/`stop` from a Lua debug hook), or verifying the delivery order between an INT3 callback and a line/count hook in the LuaJIT int3 fork.

# Procedure

1. **Probe before changing anything.** Write a throwaway C program linked against `libluajit-5.1.dll.a` (public API only) that:
   - starts a session with `luaJIT_int3_start` BEFORE installing the hook (otherwise the API returns `UNAVAILABLE`/`DISABLED` and you learn nothing);
   - installs `lua_sethook(L, hook, LUA_MASKLINE, 0)`;
   - in the hook calls `lua_getinfo(L, "f", &ar_copy)` to push the running function, then each of `arm_bc`, `cancel`, `stop`, `start`, printing the results.
   Expected baseline in this fork: `arm` is already OK (queued → mounted at the next safe point); `start`/`cancel`/`stop` were BUSY until commit "Let a Lua debug hook start, cancel and stop the session".

2. **Filter hook events to the function under test.** A line hook's first events belong to the chunk that calls the function. Compare `lua_getinfo(L,"f")` with `G.<fn>` via `lua_rawequal`, pop 3 and return early on mismatch, and make the hook one-shot with a `done` flag; otherwise the scenario is nondeterministic.

3. **Know the delivery order before writing assertions.** The trap is delivered on the dispatch of its own slot, *before* the line/count hook of that instruction, because `lj_dispatch_update()` restores `disp[BC_INT3]` at its end (BC_INT3 is below `BC_FUNCF`, so the ins-dispatch rewrite otherwise covers it). Therefore:
   - a hook that cancels the slot it belongs to still sees that callback (hits == 1);
   - a hook that cancels a *later* slot preempts it (no new hit);
   - `arm` from a hook is queued, so the current dispatch is untrapped.
   Assert exactly those, not the naive "cancel prevents the hit".

4. **Teeth.** Revert the relaxed predicate (e.g. `int3_locked` → "any hook is busy") and confirm the new group fails on the relaxed path while the hard-context group (GC hook / foreign VM event assertions) still passes. Restore afterwards.

5. **Keep hard contexts refused.** GC hook, profiler, foreign VM event, mcode/recorder/compiler must still return BUSY; extend the existing VM-event probe so `start`, `cancel`, `stop` are asserted BUSY there. Note the asymmetry: `arm` queues while recording/compiling but `start`/`cancel`/`stop` do not.

6. **Rebuild per configuration.** `mingw32-make` does not track `XCFLAGS`: always `mingw32-make clean` before each config of the matrix (GC64+ASSERT, non-GC64, `-DLUAJIT_DISABLE_JIT` → `-DSMOKE_NO_JIT`, `-DLUAJIT_DISABLE_PROFILE` → `-DSMOKE_NO_PROFILE`). Stale objects show up as "BC_INT3 opcode not found" in the harness or int3 APIs returning 4 (`UNAVAILABLE`).

7. **Docs to touch when a rule changes.** `src/luajit_rolling.h` block, `doc/ext_c_api.html` paragraphs (start's BUSY list, the hook paragraph, the arm refusal list), and `src/lj_int3.c` comment above `lj_int3_arm()`. Verify `<p>/<tt>/<b>/<i>/<pre>` counts balance in the edited section. Distinguish "refuses every call" from "refuses start/cancel/stop while arming queues" — that exact wording was caught in review.
