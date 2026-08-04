#include "ConfigPaths.hpp"

#include "config.hpp"
#include "game_info.hpp"

#include <algorithm>
#include <cstdlib>
#include <spdlog/spdlog.h>
#include <string_view>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#include <KnownFolders.h>
#include <ShlObj.h>
#pragma comment(lib, "Shell32.lib")
#endif

namespace ds::config::path {
namespace {

using namespace std::string_view_literals;

std::filesystem::path GetHomeDir() {
    auto home = std::getenv("HOME");
    if (home == nullptr) {
        home = std::getenv("USERPROFILE");
    }
    if (home == nullptr) {
        return {};
    }
    return std::filesystem::path{home};
}

std::filesystem::path GetUserDocumentsDir() {
#ifdef _WIN32
    PWSTR documents_path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Documents, KF_FLAG_DEFAULT, nullptr, &documents_path))) {
        std::filesystem::path documents_dir = documents_path;
        CoTaskMemFree(documents_path);
        return documents_dir;
    }
#endif
    const auto home_dir = GetHomeDir();
    if (home_dir.empty()) {
        return {};
    }
    return home_dir / "Documents";
}

std::filesystem::path GetPlatformKleiRootDir() {
#if defined(__linux__)
    const auto home_dir = GetHomeDir();
    if (home_dir.empty()) {
        return {};
    }
    return home_dir / ".klei";
#else
    const auto documents_dir = GetUserDocumentsDir();
    if (documents_dir.empty()) {
        return {};
    }
    return documents_dir / "Klei";
#endif
}

std::filesystem::path GetAppStorageBaseDir(std::string_view relative_path = {}) {
#if defined(__linux__)
    const auto home_dir = GetHomeDir();
    if (home_dir.empty()) {
        return {};
    }
    if (relative_path.empty()) {
        return home_dir;
    }
    const auto normalized = std::filesystem::path{relative_path}.generic_string();
    if (normalized == "Klei") {
        return home_dir / ".klei";
    }
    if (std::string_view{normalized}.starts_with("Klei/"sv)) {
        return home_dir /
               std::filesystem::path{std::string{".klei/"}.append(normalized.substr(sizeof("Klei/") - 1))};
    }
    return home_dir / std::filesystem::path{relative_path};
#else
    const auto documents_dir = GetUserDocumentsDir();
    if (documents_dir.empty()) {
        return {};
    }
    if (relative_path.empty()) {
        return documents_dir;
    }
    return documents_dir / std::filesystem::path{relative_path};
#endif
}

std::string_view GetDefaultPersistentStorageRoot() {
#if defined(_WIN32) || defined(__APPLE__)
    return "APP:Klei/"sv;
#else
    return ".klei/"sv;
#endif
}

std::filesystem::path GetKleiSaveDataDir(std::string_view ownid) {
    const auto klei_root = GetPlatformKleiRootDir();
    if (klei_root.empty()) {
        return {};
    }
    auto save_dir = klei_root / "DoNotStarveTogether";
    if (!ownid.empty()) {
        save_dir /= ownid;
    }
    spdlog::info("resolved Klei save data dir for ownid '{}' to {}", ownid, save_dir.string());
    return save_dir;
}

std::filesystem::path GetPersistentStorageRootDir(std::string_view persist_root) {
    if (persist_root.empty()) {
        return {};
    }
    auto normalized = std::string{persist_root};
    constexpr auto app_prefix = "APP:"sv;
    if (std::string_view{normalized}.starts_with(app_prefix)) {
        normalized.erase(0, app_prefix.size());
        const auto resolved_root = GetAppStorageBaseDir(normalized);
        spdlog::info("resolved persistent storage root '{}' to {}", persist_root, resolved_root.string());
        return resolved_root;
    }
    std::filesystem::path root{normalized};
    if (root.is_absolute()) {
        spdlog::info("using absolute persistent storage root {}", root.string());
        return root;
    }
    const auto base = GetHomeDir();
    if (base.empty()) {
        return {};
    }
    const auto resolved_root = base / root;
    spdlog::info("resolved relative persistent storage root '{}' to {}", persist_root, resolved_root.string());
    return resolved_root;
}

void add_path_candidate(std::vector<std::filesystem::path> &candidates,
                        const std::filesystem::path &candidate) {
    if (candidate.empty()) {
        return;
    }
    if (std::find(candidates.begin(), candidates.end(), candidate) == candidates.end()) {
        candidates.push_back(candidate);
    }
}

} // namespace

std::filesystem::path GetModConfigDataDir(std::string_view ownid, std::string_view cluster_name) {
    auto save_dir = GetKleiSaveDataDir(ownid);
    if (save_dir.empty()) {
        return {};
    }
    return save_dir / cluster_name / "mod_config_data";
}

std::filesystem::path GetModConfigDataFileName(std::string_view modname) {
    std::string_view ext = InjectorConfig::instance()->AppVersionDevPatch ? "_dev" : "";
    return std::string("modconfiguration_").append(modname).append(ext);
}

std::string read_env_or_cmd_value(const char *key) {
    char buffer[256] = {};
    InjectorConfig::getEnvOrCmdValue(key, buffer, sizeof(buffer));
    return buffer;
}

GameInfo GetServerGameInfo() {
    GameInfo game_info;
    if (auto runtime_info = readGameInfo()) {
        game_info = *runtime_info;
    }
    if (auto value = read_env_or_cmd_value("persistent_storage_root"); !value.empty()) {
        game_info.persist_root = value;
    }
    if (auto value = read_env_or_cmd_value("conf_dir"); !value.empty()) {
        game_info.config_dir = value;
    }
    if (auto value = read_env_or_cmd_value("cluster"); !value.empty()) {
        game_info.cluster_name = value;
    }
    if (auto value = read_env_or_cmd_value("shard"); !value.empty()) {
        game_info.shared_name = value;
    }
    if (game_info.persist_root.empty()) {
        game_info.persist_root = std::string{GetDefaultPersistentStorageRoot()};
    }
    if (game_info.config_dir.empty()) {
        game_info.config_dir = "DoNotStarveTogether";
    }
    if (game_info.cluster_name.empty()) {
        game_info.cluster_name = "Cluster_1";
    }
    if (game_info.shared_name.empty()) {
        game_info.shared_name = "Master";
    }
    return game_info;
}

std::vector<std::filesystem::path>
GetServerModOverridesPaths(const GameInfo &game_info,
                           const std::optional<std::string> &ownerdir_hint) {
    std::vector<std::filesystem::path> candidates;
    const auto persist_root = GetPersistentStorageRootDir(game_info.persist_root);
    if (persist_root.empty()) {
        return candidates;
    }
    const auto config_root = persist_root / game_info.config_dir;
    const auto shard_suffix =
        std::filesystem::path{game_info.cluster_name} / game_info.shared_name / "modoverrides.lua";

    if (ownerdir_hint && !ownerdir_hint->empty()) {
        add_path_candidate(candidates, config_root / *ownerdir_hint / shard_suffix);
    }

    std::error_code ec;
    if (std::filesystem::exists(config_root, ec) && std::filesystem::is_directory(config_root, ec)) {
        std::vector<std::filesystem::path> ownerdirs;
        for (const auto &entry : std::filesystem::directory_iterator(config_root, ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_directory(ec)) {
                continue;
            }
            const auto ownerdir_name = entry.path().filename().string();
            if (ownerdir_name.empty() || ownerdir_name == game_info.cluster_name) {
                continue;
            }
            ownerdirs.push_back(entry.path());
        }
        std::sort(ownerdirs.begin(), ownerdirs.end());
        for (const auto &ownerdir : ownerdirs) {
            add_path_candidate(candidates, ownerdir / shard_suffix);
        }
    }
    add_path_candidate(candidates, config_root / shard_suffix);
    return candidates;
}

bool is_supported_lua_vm_type(std::string_view value) {
    return value == "jit"sv || value == "game"sv || value == "lua51"sv || value == "51"sv ||
           value == "5.1"sv || value == "jit_gen"sv || value == "_51"sv;
}

} // namespace ds::config::path
