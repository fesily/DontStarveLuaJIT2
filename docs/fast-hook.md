# Direct Replacement Hooks

`ds::FastHook` is the x86-64 replacement interface for hooks that must avoid
Gum invocation dispatch. Its implementation is exported by Injector so plugins
share one installation registry and one pool of nearby relay pages.

```cpp
void *original = nullptr;
auto result = ds::FastHook::Install(interceptor, target, replacement, &original);
// Call original to bypass the replacement, when needed.
bool restored = ds::FastHook::Revert(interceptor, target);
```

The entry uses a five-byte `E9 rel32`. If the replacement is outside that
range, it jumps to a nearby relay containing `FF 25 00 00 00 00` followed by
the replacement address. Neither jump clobbers a register or creates a stack
frame. The custom redirect callback runs during installation only.

The wrapper uses the existing `GumInterceptorOptions.write_redirect` and
`redirect_space_hint` APIs. Gum relocates complete instructions, creates the
original trampoline, records the overwritten bytes, and restores them.
For example, a four-byte instruction followed by a five-byte call requires
nine bytes of relocation for the five-byte entry patch.

Revert uses the recorded resolved installation address, even when the caller
originally supplied a native jump thunk. Pass the original installation target
to Revert, never the returned trampoline. Revert checks the original entry
prefix before marking the record inactive; failed or deferred restoration
retains the record for retry. When batching with an outer Gum transaction,
retry Revert after ending the transaction to confirm restoration.

Install returns Gum errors directly and never falls back to ordinary replace.
An existing ordinary interceptor context is a type conflict. Entries without
five bytes of safely relocatable instructions are rejected without a patch.
Non-x86-64 hosts currently return `GUM_REPLACE_WRONG_SIGNATURE`.

Relay slots and callback records are retained for the process lifetime.
Retired relays remain immutable and executable so a thread already heading
through one is not sent into freed memory. This does not extend the lifetime
of the replacement module or of Gum's original trampoline; callers must
coordinate plugin unloading and original-function use with their execution
lifecycle. As with Gum itself, install and revert must be coordinated with
threads executing the overwritten function prologue.

`test_fast_hook` runs executable fixtures against the actual shared Gum:
near and far replacements, register preservation, original trampolines,
repeated byte-exact restoration, native thunks, transactions, RIP-relative
instructions, short entries, and conflicts with ordinary hooks.

## Validation

Windows x64 validation on October 15, 2026 used Release (`/O2 /DNDEBUG`)
and the existing shared Frida-Gum DLL, without modifying Gum sources.
All eight selected CTest cases passed: `fast_hook`, `harness_unit`,
`game_performance_unit`, and five `luajit_parity_*` cases.

An offline default-size world with seed 123456 completed under both the
embedded game Lua 5.1 and LuaJIT with JIT disabled. The single measured
`forest_map.Generate` interval was 2.635205 s for game Lua and 2.022280 s
for LuaJIT. Neither Lua nor native sampling was enabled. These single-run
observations establish successful generation, not a stable performance estimate.
The full evidence is under `builds/game-performance-20261015-fast-hook/`.
Linux/macOS execution and concurrent prologue patching were not tested.
