#pragma once

#include "ConfigSchema.hpp"
#include "PluginTypes.hpp"
#include "gameModConfig.hpp"

namespace ds::plugin {

// ConfigView SSOT merge for PluginHost::resolve (EarlyNative).
//
// `resolved` is the cascade result (ResolvedConfig.view) or any pre-filled
// ConfigView. For each key registered in `schema` that is missing from
// `resolved`, fill the schema default (late plugin keys after DynamicPluginLoader).
// Existing keys in `resolved` are never overwritten — cascade is SSOT.
//
// Prefer: BuildConfigView(host.option_schema(), resolved_config->view)
ConfigView BuildConfigView(const ConfigSchemaRegistry &schema,
                           const ConfigView &resolved);

// Compatibility: project GameJitModConfig core fields + business_options into a
// ConfigView without schema defaults. Prefer ResolvedConfig.view for Host.
// business_options is deprecated for Host; this remains for legacy unit paths.
ConfigView FromGameJitModConfig(const GameJitModConfig &config);

} // namespace ds::plugin
