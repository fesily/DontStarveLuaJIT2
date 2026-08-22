#pragma once

namespace ds::plugin {
class PluginHost;
// Phase A: register static builtin plugins (network.rpc, render.vbpool, render.angle, …).
void RegisterBuiltinPlugins(PluginHost &host);
} // namespace ds::plugin
