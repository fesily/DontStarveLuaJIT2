#pragma once

#include <cstddef>
#include <filesystem>

namespace ds::plugin {

// Move files from plugins_dir/update_pending/ into plugins_dir before LoadLibrary.
// Supports manager-written replacements and manual drops. Missing/empty pending => 0.
// Returns the number of files successfully applied.
size_t apply_pending_plugin_updates(const std::filesystem::path &plugins_dir);

// Layout consolidation (pre-LoadLibrary, same tree lock). Flat plugin modules are NOT
// supported (plugins must live in plugins/<stem>/<stem>.<ext>): a flat module/meta whose
// package dir exists is a stale leftover of the old flat installer and is removed and
// logged; a flat module without a package dir is kept but warned about (never deleted —
// it may be a manual drop the user still has to move). Returns the number of removed files.
size_t consolidate_flat_plugin_layout(const std::filesystem::path &plugins_dir);

} // namespace ds::plugin
