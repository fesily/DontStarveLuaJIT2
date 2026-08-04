#include "RegisterBuiltinPlugins.hpp"
#include "PluginHost.hpp"

namespace ds::plugin {

// Path A static registry is intentionally empty after Phase B migration.
// EarlyNative business plugins ship as dynamic modules under plugins/:
//   plugin_network_rpc  → network.rpc
//   plugin_render_vbpool → render.vbpool
//   plugin_render_angle  → render.angle
// Host still calls RegisterBuiltinPlugins before DynamicPluginLoader so the
// extension point remains for true L0-only static plugins if ever needed.
void RegisterBuiltinPlugins(PluginHost &host) {
    (void) host;
}

} // namespace ds::plugin
