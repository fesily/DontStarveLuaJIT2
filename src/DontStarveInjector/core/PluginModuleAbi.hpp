#pragma once

#include "PluginHost.hpp"

// Host expects this major string from optional ds_plugin_module_abi_version().
inline constexpr const char *DS_PLUGIN_ABI_VERSION = "1";

// Module-side export (plugin_*.dll)
#if defined(_WIN32)
#  define DS_PLUGIN_MODULE_EXPORT extern "C" __declspec(dllexport)
#else
#  define DS_PLUGIN_MODULE_EXPORT extern "C" __attribute__((visibility("default")))
#endif

// Required:
//   DS_PLUGIN_MODULE_EXPORT bool ds_plugin_module_init(ds::plugin::PluginHost *host);
// Optional:
//   DS_PLUGIN_MODULE_EXPORT const char *ds_plugin_module_abi_version();
