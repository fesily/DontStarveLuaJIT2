#include "Workshop.hpp"
#include "util/platform.hpp"

#include <algorithm>
#include <string>
#include <spdlog/spdlog.h>

namespace ds::sdk::steam {
namespace {

std::optional<std::filesystem::path> steam_root;
std::optional<std::filesystem::path> content_directory;
std::string absolute_directory;
bool directory_resolved = false;

std::optional<std::filesystem::path> GetCommandLineDirectory() {
    const auto cmds = get_cmds();
    auto iter = std::find(cmds.begin(), cmds.end(), "-ugc_directory");
    if (iter != cmds.end() && ++iter != cmds.end()) {
        spdlog::info("workshop_dir ugc_directory: {}", *iter);
        return *iter;
    }
    return std::nullopt;
}

} // namespace

void SetWorkshopDirectory(const char *folder) {
    if (folder != nullptr) {
        steam_root = folder;
        content_directory.reset();
        absolute_directory.clear();
        directory_resolved = false;
    }
}

const std::optional<std::filesystem::path> &GetWorkshopDirectory() {
    if (!directory_resolved) {
        static const auto command_line_root = GetCommandLineDirectory();
        const auto &root = command_line_root ? command_line_root : steam_root;
        if (root) {
            content_directory = *root / "content" / "322330";
        } else {
            auto fallback = std::filesystem::relative(std::filesystem::path("..") / ".." / ".." / "workshop");
            if (std::filesystem::exists(fallback)) {
                content_directory = fallback / "content" / "322330";
            }
        }
        directory_resolved = true;
    }
    return content_directory;
}

const char *GetAbsoluteWorkshopDirectory() {
    const auto &directory = GetWorkshopDirectory();
    if (!directory) {
        return nullptr;
    }
    if (absolute_directory.empty()) {
        absolute_directory = std::filesystem::absolute(*directory).generic_string();
    }
    return absolute_directory.c_str();
}

} // namespace ds::sdk::steam

const char *DS_LUAJIT_get_workshop_dir() {
    return ds::sdk::steam::GetAbsoluteWorkshopDirectory();
}
