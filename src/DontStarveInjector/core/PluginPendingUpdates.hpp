#pragma once

#include <cstddef>
#include <filesystem>

namespace ds::plugin {

// Move files from plugins_dir/update_pending/ into plugins_dir before LoadLibrary.
// Supports manager-written replacements and manual drops. Missing/empty pending => 0.
// Returns the number of files successfully applied.
size_t apply_pending_plugin_updates(const std::filesystem::path &plugins_dir);

} // namespace ds::plugin
