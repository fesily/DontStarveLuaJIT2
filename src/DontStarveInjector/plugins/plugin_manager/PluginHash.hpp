#pragma once
// Pure SHA-256 helpers for plugin package verification (offline-testable).

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds::plugin_manager {

// Lowercase hex digest of `data`.
std::string sha256_hex(std::string_view data);

// Lowercase hex digest of file contents; nullopt on I/O error.
std::optional<std::string> sha256_file_hex(const std::filesystem::path &path);

// Case-insensitive compare of hex digests (ignores optional "0x" prefix / whitespace).
bool sha256_hex_equal(std::string_view actual_hex, std::string_view expected_hex);

} // namespace ds::plugin_manager
