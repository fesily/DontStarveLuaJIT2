#include "PluginPendingUpdates.hpp"

#include <cstdio>
#include <system_error>

namespace ds::plugin {
namespace {

bool try_rename(const std::filesystem::path &from, const std::filesystem::path &to, std::error_code &ec) {
    ec.clear();
    std::filesystem::rename(from, to, ec);
    return !ec;
}

bool try_copy_remove(const std::filesystem::path &from, const std::filesystem::path &to, std::error_code &ec) {
    ec.clear();
    std::filesystem::copy_file(from, to, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        return false;
    }
    std::error_code remove_ec;
    std::filesystem::remove(from, remove_ec);
    if (remove_ec) {
        // Destination is already updated; pending residue is best-effort cleanup.
        std::fprintf(stderr, "[PluginPendingUpdates] remove_pending_failed: %s (%s)\n", from.string().c_str(),
                     remove_ec.message().c_str());
    }
    return true;
}

bool apply_one(const std::filesystem::path &from, const std::filesystem::path &to) {
    std::error_code ec;
    // Prefer atomic replace when the OS allows overwrite-on-rename.
    if (std::filesystem::exists(to, ec)) {
        std::filesystem::remove(to, ec);
        // Fall through either way: rename or copy+remove will report failure.
    }
    if (try_rename(from, to, ec)) {
        return true;
    }
    if (try_copy_remove(from, to, ec)) {
        return true;
    }
    std::fprintf(stderr, "[PluginPendingUpdates] apply_failed: %s -> %s (%s)\n", from.string().c_str(),
                 to.string().c_str(), ec.message().c_str());
    return false;
}

} // namespace

size_t apply_pending_plugin_updates(const std::filesystem::path &plugins_dir) {
    const auto pending_dir = plugins_dir / "update_pending";
    std::error_code ec;
    if (!std::filesystem::is_directory(pending_dir, ec)) {
        return 0;
    }

    size_t applied = 0;
    for (const auto &entry : std::filesystem::directory_iterator(pending_dir, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file(ec)) {
            continue;
        }

        const auto &from = entry.path();
        const auto to = plugins_dir / from.filename();
        if (apply_one(from, to)) {
            ++applied;
            std::fprintf(stderr, "[PluginPendingUpdates] applied: %s\n", to.string().c_str());
        }
    }
    return applied;
}

} // namespace ds::plugin
