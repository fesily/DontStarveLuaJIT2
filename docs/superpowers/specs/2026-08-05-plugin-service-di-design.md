# Plugin Service Dependency + DI Design

Date: 2026-08-05  
Status: approved for implementation

## Problem

1. Peer plugins resolve optional providers by hardcoding DLL names (`GetProcAddress("plugin_core_vm.dll")`) or free-form `ds_host_lookup_service` with no gate.
2. Free export `ds_host_register_service` allows registration at any time (including `load()`), so hard service deps cannot be checked at `resolve`.
3. Plugin-id `depends` already exists; **service-level** requires/injection does not.

## Goals

- Manifest **declares** hard/soft service requirements.
- `PluginHost::resolve` **fails** candidates missing hard services (`MissingService`).
- `load_phase` **injects** resolved function pointers into `PluginContext.services`.
- Service **registration is only possible through `PluginHost` during module init window** — API shape enforces location; no free register export for plugins.

## Non-goals

- Service version negotiation.
- Unregister / hot-swap (DLL sticky).
- Auto-derive plugin-id `depends` from service names.
- Constructor injection / new `IPlugin` virtuals.
- Changing `ds_plugin_module_init(PluginHost*)` signature (Host *is* the registrar).

## Data model

```cpp
// PluginManifest
std::vector<std::string> requires_services;       // hard
std::vector<std::string> soft_requires_services;  // soft

// PluginFailReason
MissingService,   // hard service absent at resolve; detail = service name

// PluginContext
std::unordered_map<std::string, void*> services;  // Host-filled before load()
```

## Registration window (API enforcement)

| API | Who | When allowed |
|-----|-----|----------------|
| `PluginHost::register_service(name, fn)` | Provider plugins | Only while `registration_open_` |
| `PluginHost::register_plugin` / `register_option_schema` | Same | Same window |
| `PluginHost::begin_module_registration()` / `end_module_registration()` | Loader / tests | Around each `ds_plugin_module_init` |
| `ds_host_lookup_service` | Anyone | Always (escape hatch / non-load paths) |
| `ds_host_register_service` | **Removed** from plugin-facing ABI | — |

Internal table stays in `PluginServices.cpp`; only Host (and unit tests via Host, or `DS_PLUGIN_HOST_STATIC` direct table helpers if needed) writes it.

`DynamicPluginLoader::load_all`:

```text
for each module:
  host.begin_module_registration()
  ok = init(&host)
  host.end_module_registration()
```

Outside the window, `register_*` returns false (fail-fast, no throw).

Under `DS_PLUGIN_HOST_STATIC` (unit tests), default `registration_open_ = true` so existing graph tests need minimal change; production Injector starts closed and only opens around module init.

## Resolve / load sequence

```text
module_init (window open)
  register_option_schema / register_plugin / register_service

refresh_cascade → BuildConfigView

PluginHost::resolve
  1. options + can_load
  2. conflicts (plugin id)
  3. hard plugin-id depends (fixpoint)
  4. NEW: for each candidate, every requires_services name
        must lookup_service(name) != nullptr
        else Failed(MissingService, name)
  5. cycle detection (plugin-id depends only)

PluginHost::load_phase
  for each plugin in topo order:
    PluginContext ctx = last_ctx_
    ctx.services.clear()
    for name in requires_services:
      ctx.services[name] = lookup(name)   // non-null by resolve
    for name in soft_requires_services:
      if (fn = lookup(name)) ctx.services[name] = fn  // omit if missing
    plugin->load(ctx)
```

## Consumer / provider conventions

**Provider** (`module_init`):

```cpp
host->register_service("ds_core_vm_get_game_lua_context",
                       reinterpret_cast<void*>(&ds_core_vm_get_game_lua_context));
```

**Consumer** (manifest + load):

```cpp
man.requires_services = {"ds_core_vm_get_game_lua_context"};
// load:
auto *fn = reinterpret_cast<GetFn>(ctx.services.at("ds_core_vm_get_game_lua_context"));
```

`VmServices::TryGetGameLuaContext()` remains valid for non-load hot paths via lookup; prefer `ctx.services` inside `load()`.

## First declarations

| Plugin | requires_services |
|--------|-------------------|
| `sim.lagcomp` | `ds_core_vm_get_game_lua_context` |
| `debug.profiler` | soft or hard on same (prefer soft if partial function without VM is desired; default **soft** so profiler can still attach Tracy without core.vm) |

Providers already register in `module_init` after this migration.

## Migration

1. Add types + Host APIs + resolve/load injection.
2. Loader begin/end window.
3. Replace every `ds_host_register_service` in plugins with `host->register_service`.
4. Remove `DONTSTARVEINJECTOR_API ds_host_register_service` export (keep lookup).
5. Tests: service missing → MissingService; present → inject map; window closed → register fails.

## Risks

- Plugins that stashed `PluginHost*` and register after init: **intentionally broken** by window.
- Service registered only in `load()`: **impossible** via Host API; resolve hard-deps stay sound.
- Order: all modules init (and register services) before any `resolve` — already true today.

## Success criteria

- No plugin includes free register export for services.
- `sim.lagcomp` fails resolve when core.vm absent (hard service).
- `load()` receives non-empty `ctx.services` for declared names when present.
- Existing plugin-id depends/conflicts tests still pass.
- L-G present PASS with core.vm present.
