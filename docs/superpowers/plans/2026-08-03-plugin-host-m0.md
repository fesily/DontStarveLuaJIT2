# PluginHost M0 Implementation Plan

> **For agentic workers:** Execute task-by-task with TDD. Spec: `docs/superpowers/specs/2026-08-03-plugin-architecture-design.md` §5, §6, §12.4–12.5, §10 M0.

**Goal:** Ship pure-logic `PluginHost` + option rules with L-A/L-B ctest gates; `Inject`/modmain remain linear (empty registry).

**Architecture:** Frida-free Host in `src/DontStarveInjector/core/`; tests link only Host sources. Fake plugins in test TU.

**Tech Stack:** C++23, CMake `add_test`, assert+printf style like `test_buffer_name_pool.cpp`.

## Global Constraints

- Path A static registry; fail-fast deps (D2); sticky unload default (D4).
- No Frida/game in unit tests.
- Structured `PluginEvent` oracle — not log scraping.
- M-G dedicated harness is **next** after M0 green, not in this plan's code.

---

### Task 1: Host API headers + option rules skeleton

**Files:**
- Create: `src/DontStarveInjector/core/PluginTypes.hpp`
- Create: `src/DontStarveInjector/core/PluginOptionRules.hpp`
- Create: `src/DontStarveInjector/core/PluginOptionRules.cpp`
- Create: `src/DontStarveInjector/core/PluginHost.hpp`
- Create: `src/DontStarveInjector/core/PluginHost.cpp`

**Interfaces:**
- Produces: `PluginPhase`, `PluginStatus`, `PluginFailReason`, `PluginEvent`, `PluginManifest`, `IPlugin`, `ConfigView`, `PluginContext`, `PluginHost::{register_plugin,resolve,load_phase,unload_plugin,events,status,loaded_order}`, `EvaluateOptionRule`.

### Task 2: L-A host graph tests (RED then GREEN)

**Files:**
- Create: `tests/plugin/test_plugin_host_graph.cpp`
- Modify: `tests/CMakeLists.txt`

### Task 3: L-B option rules tests

**Files:**
- Create: `tests/plugin/test_plugin_option_rules.cpp`
- Modify: `tests/CMakeLists.txt`

### Task 4: Empty RegisterBuiltinPlugins stub (no behavior change)

**Files:**
- Create: `src/DontStarveInjector/core/RegisterBuiltinPlugins.cpp`
- Create: `src/DontStarveInjector/core/RegisterBuiltinPlugins.hpp`
- Optional later: call from Inject — M0 allows still linear; stub only registers nothing.

### Task 5: Verify ctest

Run `plugin_host_graph` and `plugin_option_rules`.

---
