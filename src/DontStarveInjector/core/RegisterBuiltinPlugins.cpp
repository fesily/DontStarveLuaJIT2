#include "RegisterBuiltinPlugins.hpp"
#include "PluginHost.hpp"

namespace ds::plugin {

// Path A static registry is intentionally empty after Phase B migration.
// EarlyNative business plugins ship as dynamic modules under plugins/:
//   plugin_network_rpc  → network.rpc
//   plugin_network_sim  → network.sim
//   plugin_save_fork    → save.fork
//   plugin_render_vbpool → render.vbpool
//   plugin_render_angle  → render.angle
// Config options are schema-driven (ConfigView SSOT): plugins register option
// schema in ds_plugin_module_init; L0 also seeds core + builtin business schema
// before load_all so cascade parse and BuildConfigView share the same keys.
// Host still calls RegisterBuiltinPlugins before DynamicPluginLoader so the
// extension point remains for true L0-only static plugins if ever needed.
void RegisterBuiltinPlugins(PluginHost &host) {
    (void) host;
}

} // namespace ds::plugin
