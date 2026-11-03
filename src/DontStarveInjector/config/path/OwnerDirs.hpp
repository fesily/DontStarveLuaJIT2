#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace ds::config::path {

// First-level owner directories under the Klei game root (`DoNotStarveTogether`),
// excluding `cluster_name` itself (the shard lives directly under the root) and
// returning them sorted.
//
// Names are compared as path components and never narrowed. A save folder whose
// name the active ANSI code page cannot represent (a GBK name stored
// byte-per-character as Latin-1) makes `std::filesystem::path::string()` throw
// ERROR_NO_UNICODE_TRANSLATION; that must not abort the caller, so the walk is
// best-effort and stops early, reporting why through `stop_reason` (optional).
std::vector<std::filesystem::path> list_owner_dirs(const std::filesystem::path &config_root,
                                                   const std::filesystem::path &cluster_name,
                                                   std::string *stop_reason = nullptr);

} // namespace ds::config::path
