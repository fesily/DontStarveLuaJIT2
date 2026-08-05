#pragma once
// Safe zip extract for plugin packages: path-traversal reject + allowlist.

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace ds::plugin_manager {

// True if zip entry name is unsafe (absolute, drive, or contains `..` segment).
bool zip_entry_is_unsafe(std::string_view name);

// Basename of a zip entry after normalizing separators; empty if unsafe.
std::string zip_entry_safe_basename(std::string_view name);

// Default allowlist when manifest files[] is absent: top-level plugin_* modules + meta.
bool zip_entry_matches_default_allowlist(std::string_view basename);

// Extract allowlisted entries from `zip_path` into `dest_dir`.
// - Rejects unsafe names (`..`, absolute, nested path escapes).
// - If `allow_files` is non-empty: only those basenames (exact).
// - Else: only top-level plugin_* modules (.dll/.so/.dylib) and plugin_*.meta.json.
// Returns number of files written, or nullopt with *err on hard failure.
// Partial writes may exist on failure; caller may clean temp dirs.
std::optional<size_t> extract_plugin_zip(const std::filesystem::path &zip_path,
                                         const std::filesystem::path &dest_dir,
                                         const std::vector<std::string> &allow_files,
                                         std::string *err);

// Open zip from memory buffer (for tests / download-in-memory). Same rules as file path.
std::optional<size_t> extract_plugin_zip_memory(const void *data, size_t size,
                                                const std::filesystem::path &dest_dir,
                                                const std::vector<std::string> &allow_files,
                                                std::string *err);

} // namespace ds::plugin_manager
