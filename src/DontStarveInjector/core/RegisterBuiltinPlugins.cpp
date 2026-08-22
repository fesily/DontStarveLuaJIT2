#include "RegisterBuiltinPlugins.hpp"
#include "PluginHost.hpp"

namespace ds::plugin {

// Path A static registry is intentionally empty after Phase B migration.
// EarlyNative plugins ship as dynamic modules under plugins/:
//   plugin_core_vm       → core.vm   (required JIT path; Signature + GameLua)
//   plugin_network_rpc   → network.rpc
//   plugin_network_sim   → network.sim
//   plugin_save_fork     → save.fork
//   plugin_sim_lagcomp   → sim.lagcomp
//   plugin_render_vbpool → render.vbpool
//   plugin_render_shadow → render.shadow
//   plugin_render_angle  → render.angle
//   plugin_debug_profiler → debug.profiler (Tracy / FullGC / FrameGC; optional)
//   plugin_dummy         → debug.dummy
// Config options are schema-driven (ConfigView SSOT): plugins register option
// schema in ds_plugin_module_init; L0 also seeds core + builtin business schema
// before load_all so cascade parse and BuildConfigView share the same keys.
// Host still calls RegisterBuiltinPlugins before DynamicPluginLoader so the
// extension point remains for true L0-only static plugins if ever needed.
// core.vm is required at runtime (force-loaded by CoreVmBootstrap); still dynamic MODULE.
// Do not register core.vm or debug.profiler here — both are dynamic
// modules (missing DLL soft-skips that feature; inject continues).
void RegisterBuiltinPlugins(PluginHost &host) {
    (void) host;
}

} // namespace ds::plugin
