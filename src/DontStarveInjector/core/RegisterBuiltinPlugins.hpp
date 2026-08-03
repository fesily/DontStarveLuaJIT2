#pragma once

namespace ds::plugin {
class PluginHost;
// Phase A: register static builtin plugins (M2+: network.rpc EarlyNative, …).
void RegisterBuiltinPlugins(PluginHost &host);
} // namespace ds::plugin
