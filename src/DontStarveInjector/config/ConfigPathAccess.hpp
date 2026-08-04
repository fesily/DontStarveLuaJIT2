#pragma once
// Temporary internal path/identity helpers for config sources (CF-S2).
// Physical move into config/path/ is Task 4.
#include "game_info.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds::config::path {

struct ResolvedModIdentity {
    std::string canonical_modname;
    std::string modname;
    std::string modid;
    std::vector<std::string> aliases;
};

ResolvedModIdentity build_mod_identity();

std::filesystem::path GetModConfigDataDir(std::string_view ownid,
                                          std::string_view cluster_name = "client_save");
std::filesystem::path GetModConfigDataFileName(std::string_view modname);

GameInfo GetServerGameInfo();
std::vector<std::filesystem::path>
GetServerModOverridesPaths(const GameInfo &game_info,
                           const std::optional<std::string> &ownerdir_hint);

std::string read_env_or_cmd_value(const char *key);

bool is_supported_lua_vm_type(std::string_view value);

} // namespace ds::config::path
