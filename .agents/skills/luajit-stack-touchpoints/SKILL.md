---
name: luajit-stack-touchpoints
description: "Use when planning/modifying LuaJIT stack handling (dual-stack, deep C recursion, yield across C frames, cframe changes) on Windows x64; maps verified touchpoints and invariants."
---

# LuaJIT stack surgery touchpoints (Win64 x64, GC64, LJ_FR2)

Repo: C:/Users/fesil/LuaJIT, v2.1 (2.1.1763318511). Verify line numbers against current tree before editing.

## Current model (facts)
- Virtual stack per lua_State: frames are 2-slot headers `[base-2]=GCfunc, [base-1]=ftsz`; kinds FRAME_LUA/C/CONT/VARG/CP/PCALL/PCALLH (lj_frame.h:25-51). Frame pop never uses RSP (ftsz delta or bc_a(PC[-1])).
- Native side: L->cframe = current VM entry frame's RSP. cframe offset table (Win64 GC64): MULTRES+32, NRES+80, ERRF+84, L+88, PC+96, PREV+104, CFRAME_SIZE=80 (lj_frame.h:141-157). Push sites: vm_x64.dasc:633/673/590, lj_ccallback.c:734-738. Readers: lj_dispatch.c:416-421/537-543/556-562, lj_snap.c:962-963, lj_trace.c:936, lj_debug.c:63-97, lib_base.c:599/621-623, lj_api.c:1185/1190/1231.
- VM entry frame: fixed 72B (4 pushes + sub rsp,40), described by hand-written .pdata/.xdata in host/buildvm_peobj.c:274-322. SEH contract: establisher frame == cframe (lj_err.c:258-260); RtlUnwindEx(f, lj_vm_unwind_c_eh|ff_eh, errcode) at lj_err.c:320-329. vm_ffi_call has its own handler-less .pdata entry and must stay last function in object (:2919).
- RSP rewritten wholesale only at: vm_unwind_c (:497 mov rsp,CARG1), vm_unwind_ff (:518), vm_exit_interp (:2516), BC_JLOOP (:4764).
- GC scans [stack+1+LJ_FR2, top) linearly (lj_gc.c:311-313); ftsz slots harmless (tag bits 0). Growth: lj_state.c:109-153 (LJ_STACK_MAX=65500, relimitstack after error).
- FFI: outbound lj_ccall_func builds CCallState on C stack then vm_ffi_call calls on same stack; inbound vm_ffi_callback runs interpreter on caller's OS stack. No depth limit; STATUS_STACK_OVERFLOW not caught (lj_err.c:283-285).

## Dual-stack design (approved conclusion)
- Phase 1: keep cframe anchored on OS stack; switch only C callees (BC_FUNCC/FUNCCW, vm_ffi_call, vm_ffi_callback) to managed VirtualAlloc native stack segments (commit all pages, guard page at bottom; guard fault → LJ_ERR_STKOV). New src/lj_nstack.c/h: segments, TLS-per-thread (callbacks may enter on any thread), enter/leave trampolines in dasc.
- Error propagation in phase 1: on exception inside managed segment, use internal unwinding (LJ_UNWIND_EXT=0 path, lj_err.c:775-781) to land on OS anchor, then existing vm_unwind_c/ff. Do NOT move VM entry frames off OS stack (breaks .pdata/RtlUnwindEx contract).
- Phase 2: per-coroutine native stacks for yield across C frames; remove L->cframe!=NULL → LJ_ERR_CORUN restriction (lib_base.c:621-623, lj_api.c:1229-1239); needs resume/yield protocol changes.
- JIT: inlined FFI calls bypass vm_ffi_call; for phase 1 disable FFI recording (noffi) or patch lj_crecord/asm call sequences.
- Unchanged: lj_gc.c, lj_frame.h, lj_dispatch.c, hooks, snap restore, lj_mcode.c.

## Verification recipe
1. Minimal prototype: switch only vm_ffi_call to a big committed buffer; run C recursion 1e6 deep; assert no crash, correct return, error via vm_unwind_ff.
2. Matrix: nested Lua↔C recursion (expect LJ_ERR_STKOV not crash), FFI callback nesting, nested pcall error crossing managed segment, coroutine suspend/resume, hooks/debug.getinfo.
3. Run luajit2-test-suite/ + dontstarve-branch soak scripts.
