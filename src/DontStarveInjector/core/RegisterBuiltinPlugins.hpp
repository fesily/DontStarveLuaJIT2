#pragma once

namespace ds::plugin {
class PluginHost;
// Phase A: register static builtin plugins. M0: no-op empty registry.
void RegisterBuiltinPlugins(PluginHost &host);
} // namespace ds::plugin
