---
name: etw-provider-lock-discipline
description: "Audit and fix ETW publisher lock contention: measure in-lock write cost, move EventWrite out of the hot lock via refcounted write batches, two-phase worker shutdown outside the lifecycle lock, plus verification and build gotchas."
---

# When

An ETW provider (or any diagnostic publisher) writes into a global/process-wide cache under a lock, and you must decide whether that lock causes contention: "review lj_etw for lock contention", "EventWrite is inside the lock", latency spikes while a session listens, VM threads or VM create/close stalling during a rundown.

# 1. Map the critical sections before judging

- Enumerate every function that takes the lock and what it does inside. A quick scanner over the source (brace-match each function; list Acquire/Release and EventWrite-style calls with counts) immediately shows which writes are inside.
- Distinguish the hot lock (touched per trace/event) from the cold one (module start/stop, VM create/destroy). Only the hot lock justifies a refactor.
- Quantify the hold time, not the total cost: total CPU does not show lock hold. Two usable measurements:
  1. Compile N distinct traces via loadstring (raise maxtrace), time the commit loop with and without a listening session; the delta is the in-lock write cost per trace.
  2. Time a bulk unpublish (etw(false) or a forced rundown) with N records, same two session states; delta/N is the in-lock cost per record. os.clock() has millisecond resolution: use N of 20k or more so the operation is measurable, and take the min of 3 runs.
- Create the capture session from outside the process: logman create trace -p "{GUID}" 0x3 4 -nb 64 256 -o <absolute etl> -ets. On this machine logman -b fails with "参数错误" while -nb works. A real listening session is required, otherwise EventEnabled short-circuits and you measure nothing.

# 2. Move the writes out (refcount + batch), never the state

- Keep the lock for list, flag and generation mutations only. Give each published payload a reference count whose parts are explicit: (a) the owner pointer (for example T->etw_entry), (b) list membership (live or retired), (c) each active writer.
- Under the lock: link or unlink, and either borrow (refs++) or hand over an unlinked list reference, chaining the node into a batch (wnext). After unlocking: write the events from the batch, then release one reference per node and free what reaches zero.
- Unlink-then-unpublish must not clear the owner pointer (only the owning VM's destroy path may). That is why unpublish moves records to a retired list and leaves freeing to the owner.
- Verify statically afterwards: scan each lock region for write calls; expect zero.

# 3. Two-phase worker shutdown (join outside the lock)

- State machine DOWN / UP / STOPPING plus a process-lifetime manual-reset "stop done" event.
- stop_begin (under the lock): set STOPPING, request stop and SetEvent, hand the thread handle out, clear the global handle. stop_join (without the lock): wait with a timeout, emit a one-shot diagnostic on timeout, then keep waiting because EventUnregister requires the thread to be gone. stop_finish (under the lock): unregister, close the wake event, set DOWN, signal stop_done.
- Concurrent initstate and enable paths wait on stop_done instead of entering the transition; a new start must refuse while STOPPING and be retried.
- Trap that costs 40 s: a thread that stops the worker itself must take the lifecycle lock directly after its own join. Calling the "wait until idle" helper there waits on its own not-yet-signalled stop_done (8 retries x 5 s). Symptom: one scenario grows from about 9 s to about 47 s, and the suite grows by an exact multiple of the timeout.

# 4. Verify

- Existing scenario suite on both variants plus the full lane; compare per-test wall time with the pre-change build (no added waits is the success signal for the shutdown rework).
- Static: no write inside any hot-lock region; every join call site immediately follows the matching unlock.
- Build-environment gotchas seen while doing this:
  - the CMake cache can revert LUAJIT_TEST_ETW to OFF; re-run the preset with -DLUAJIT_TEST_ETW=ON.
  - LNK1168 or LNK1201 on lua51DS.dll or lua51DS.pdb means leftover test processes or mspdbsrv.exe still own them; kill those and delete the pdb.
  - a cancelled background shell may keep spawning the test exe; find the cmd.exe whose CommandLine matches and kill that too.

# Known leftovers to state instead of hiding

- Bulk writes performed by the on/off transition itself still sit under the cold lifecycle lock (affects VM create/close only during an explicit switch).
- A rundown replay racing an unpublish can emit a duplicate load/unload pair for one payload; consumers key by identity, so it is not a correctness bug - say so explicitly.
