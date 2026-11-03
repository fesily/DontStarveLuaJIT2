#include "config/path/OwnerDirs.hpp"

#include <algorithm>
#include <exception>

namespace ds::config::path {

std::vector<std::filesystem::path> list_owner_dirs(const std::filesystem::path &config_root,
                                                   const std::filesystem::path &cluster_name,
                                                   std::string *stop_reason) {
    std::vector<std::filesystem::path> owner_dirs;
    if (config_root.empty()) {
        return owner_dirs;
    }
    std::error_code ec;
    if (!std::filesystem::exists(config_root, ec) || !std::filesystem::is_directory(config_root, ec)) {
        return owner_dirs;
    }
    try {
        for (const auto &entry : std::filesystem::directory_iterator(config_root, ec)) {
            if (ec) {
                break;
            }
            if (!entry.is_directory(ec)) {
                continue;
            }
            const auto name = entry.path().filename();
            if (name.empty() || name == cluster_name) {
                continue;
            }
            owner_dirs.push_back(entry.path());
        }
    } catch (const std::exception &e) {
        if (stop_reason != nullptr) {
            *stop_reason = e.what();
        }
    }
    std::sort(owner_dirs.begin(), owner_dirs.end());
    return owner_dirs;
}

} // namespace ds::config::path
