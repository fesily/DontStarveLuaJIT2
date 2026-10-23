#pragma once
// Path candidates and env helpers for config cascade (CF-S3).
#include "ModIdentity.hpp"
#include "game_info.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ds::config::path {

std::filesystem::path GetModConfigDataDir(std::string_view ownid,
                                          std::string_view cluster_name = "client_save");

// <klei>/DoNotStarveTogether/<ownid>/client_save - the client's working "save"
// root and the root DST's mod io sandbox uses for relative mod paths. With an
// empty ownid the most recently written client_save is used (Steam identity
// unavailable); empty when nothing matches.
std::filesystem::path GetClientSaveDir(std::string_view ownid);
std::filesystem::path GetModConfigDataFileName(std::string_view modname);

GameInfo GetServerGameInfo();
std::vector<std::filesystem::path>
GetServerModOverridesPaths(const GameInfo &game_info,
                           const std::optional<std::string> &ownerdir_hint);

std::string read_env_or_cmd_value(const char *key);

bool is_supported_lua_vm_type(std::string_view value);

} // namespace ds::config::path
