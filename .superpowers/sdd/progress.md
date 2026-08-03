# SDD Progress — plugin architecture

Base branch: master (user executing on master with prior M0/M-G commits)

## Complete

- M0 PluginHost + L-A/L-B: commits through 308034c
- M-G L-G harness green: dbd9ae6, a41d407

## Plan

`docs/superpowers/plans/2026-08-03-plugin-migration-m1-m6.md`

## Tasks

- Task 1: pending (wire host into Injector)
- Task 2: pending (Lua host)
- Task 3: pending (save.fork)
- Task 4: pending (lagcomp + netsim)
- Task 5: pending (network.rpc/entity)
- Task 6: pending (render angle/vbpool)
- Task 7: pending (jit/gc/profiler/fps)
- Task 8: pending (M5 trunk L-F)
- Task 9: pending (M6 docs)
- Task 10: pending (final verification)

Task 1: complete (commits a41d407..8802026, controller review: empty registry no-op OK; NetworkOpt default noted)
Task 2: complete (commits 8802026..8f315ce, L-C 21 PASS)
Task 3: complete (b0ebb63, save.fork plugin)
Task 4: complete (c9f272d, lagcomp+netsim)
Task 5: complete (90114ba, network.rpc+entity)
Task 6: complete (664f7d2, render plugins)
Task 7: complete (48fd06a, jit/gc/profiler/fps/tailcall)
Task 8: complete (93dc0c0, L-F green)
Task 9: complete (04d2b03, docs/plugin-system.md)
Task 10: complete (final verification green: host/lua/L-F/L-G/fork_save)
