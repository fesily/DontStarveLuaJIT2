# Pred-ON Authority vs Display

**Date:** 2026-08-13
**Status:** Approved (design dialogue)
**Scope:** Stop fighting `EnableMovementPrediction(false)`. Use Klei's prediction stack for display/anim. Combat stays server-authoritative. No display extrapolation.

**Related:**

- Investigation: `docs/investigation-movement-jitter-luajit.md` (pred-OFF = snapshot + `Teleport`)
- Harmful experiment (reverted): `client.smooth` display extrapolation
- Diagnostic only (not product): `plugin_client_anim` local_a0 / XOR / flAnimTime watch

---

## 1. Problem

Players turn **movement prediction OFF** so the visible body matches the server hitbox ("I walked out of range but still got hit"). Pred OFF also strips locomotor + client SG and makes AnimState a pure replica. Position becomes hard `Deserialize → SetPosition/Teleport`. Walk cycle comes from the network. Visual quality is poor; LuaJIT makes the same snaps more obvious.

Pred-OFF anim hooks (`local_a0`, `XOR BL,BL`, Lua `PlayAnimation`, hardware watch) proved:

- Network `AnimTime` writes are gated by Deserialize `BL` (`exe+0x9FE5E`). Forcing `BL=1` stops them.
- Remaining `time_back` in the probe is **local Update wrap** (`FUN_140098860`: when `t >= 2L`, `t = fmod(t, L) + L`). `sAnim::GetFrame` loop mode already `fmod`s — wrap is render-seamless.
- Mid-walk jump with pred OFF is **position authority**, not anim rewind.

That path is too coupled to rebuild. The product question is not "pred OFF but smooth"; it is "two coordinates, small lie."

---

## 2. Locked decisions

| # | Decision | Choice |
|---|----------|--------|
| P1 | Combat / hitbox | **Server position only.** Client display may lead. Walking out of range can still be hit. |
| P2 | Display / anim | **Stock `EnableMovementPrediction(true)`.** SG + locomotor + native `local_a0` skip of PlayMode/AnimHash/AnimTime. |
| P3 | Server does not chase client | Server simulates inputs independently. Client reconciles display toward server via `pPredictionHistory`. |
| P4 | Display extrapolation | **Forbidden.** `client.smooth` raised residual and caused recoil. |
| P5 | Second Transform / render offset | **Forbidden** in this spec. One entity transform. |
| P6 | Pred-OFF anim product path | **Abandoned.** Remove or permanently disable `plugin_client_anim` gate / XOR / watch / local `PlayAnimation` drive. Keep git history. |
| P7 | Residual / hard snap | Use engine history miss → `Teleport`. Do **not** invent a blend radius until JIT miss-rate is shown ≫ game VM. |
| P8 | First delivery | Pred ON + delete pred-OFF anim work. Measure. No new reconcile math. |

---

## 3. Architecture

```
Input ──► client SG / locomotor (predicted display + anim)
       └─► RPC.DirectWalking / actions ──► server sim (combat truth)
                                              │
Server snapshot ──► CheckTransformationPredictionHistory
                       match  → consume history (no snap)
                       miss   → Teleport (honest hard correct)
Anim replica ──► local_a0 true → skip PlayMode / AnimHash / AnimTime
```

Combat queries server. `ThePlayer` transform is the predicted display pose. That is DST's existing split. This spec does not add a ghost mesh or a replica-position getter (out of scope unless a later spec asks for an honesty cue).

---

## 4. What we stop doing

- Hooking `cAnimStateComponent::Deserialize` to force `BL=1` (all-entity or local-only).
- Hardware watchpoints on `flAnimTime`.
- Lua `PlayAnimation(run_*)` / `idle` while pred OFF to fake a client SG.
- Any display integration that **adds** predicted delta beyond the last server sample (extrapolation).

Jitter probe may stay as a measurement tool. Its `time_back` on looping anims is **not** a network fault (wrap + `GetCurrentAnimationTime` fmod). Do not treat it as a pass/fail for this spec.

---

## 5. Data flow (pred ON, unchanged)

1. Client tick: locomotor integrates; SG plays `run_loop` / `idle`.
2. Client sends **directions**, not positions.
3. Server integrates the same intent; serializes transform + anim dirty bits.
4. Client transform Deserialize: history compare; snap only on miss.
5. Client anim Deserialize: `IsPredictingMovement && IsServerReady` → skip time/hash/mode.

LuaJIT may change snapshot clustering / `dt`. That is the only remaining jitter hypothesis **after** P8. Investigate `FrameBegin` dt, history miss count, `Teleport` rate — not AnimTime writes.

---

## 6. Error / edge cases

| Case | Behavior |
|------|----------|
| Pred toggled OFF by user | Stock Klei path. We do not paper over it. Optional: log once that pred OFF is unaided. |
| Large correction (teleport, stun, boat) | Hard snap. Correct. |
| History overflow (`WAITING`) | Engine already degrades. Do not add a side buffer. |
| Missing `core.vm` | Unrelated; pred is native. |

---

## 7. Verification

1. Pred ON, game VM vs JIT, same walk. No `plugin_client_anim` drive.
2. Pass: mid-walk visual not worse than game VM; no new recoil vs stock pred ON.
3. Probe (if on): `EnablePred` events; transform `Deserialize`/`SetPos` still occur; do **not** require zero Lua `time_back`.
4. Pred OFF smoke: game still runs; feature simply absent.

---

## 8. Non-goals

- Server lag compensation / `sim.lagcomp` (already out of visual scope).
- Client-authoritative movement (server adopts client pos).
- Dual draw (predicted mesh + server ghost) — later spec only.
- Soft-blend of history misses — later spec, only with miss-rate evidence.
- Fixing pred-OFF snapshot cadence.

---

## 9. Self-review

- No TBD/TODO.
- P1–P8 do not contradict §3–§8.
- Single implementation slice: remove pred-OFF anim product code; document pred ON as the path. No new native reconcile.
- "Jitter" here means mid-walk visual pop under pred ON, not probe `time_back`.
