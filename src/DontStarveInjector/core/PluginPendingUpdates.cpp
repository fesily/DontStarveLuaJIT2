#include "PluginPendingUpdates.hpp"

#include <cstdio>
#include <system_error>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace ds::plugin {
namespace {

std::filesystem::path sibling_temp_path(const std::filesystem::path &dest) {
    const auto parent = dest.parent_path().empty() ? std::filesystem::path(".") : dest.parent_path();
#if defined(_WIN32)
    const auto tag = std::to_string(GetCurrentProcessId());
#else
    const auto tag = std::to_string(static_cast<unsigned>(::getpid()));
#endif
    return parent / (dest.filename().string() + ".ds_pending_tmp_" + tag);
}

// Prefer rename-over-existing when the OS supports it. Otherwise stage a sibling
// temp next to dest and only then replace. Never delete a live module first.
bool apply_one(const std::filesystem::path &from, const std::filesystem::path &to) {
    std::error_code ec;

    // Fast path: rename pending onto dest (atomic replace on POSIX; may fail on Windows if dest exists).
    std::filesystem::rename(from, to, ec);
    if (!ec) {
        return true;
    }

    // Stage durable content beside dest, then replace. Keep `from` until success.
    const auto tmp = sibling_temp_path(to);
    std::filesystem::remove(tmp, ec);
    ec.clear();
    std::filesystem::copy_file(from, tmp, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        std::fprintf(stderr, "[PluginPendingUpdates] stage_failed: %s -> %s (%s)\n", from.string().c_str(),
                     tmp.string().c_str(), ec.message().c_str());
        return false;
    }

    // Prefer rename temp over dest (no pre-delete).
    ec.clear();
    std::filesystem::rename(tmp, to, ec);
    if (!ec) {
        std::error_code rm_ec;
        std::filesystem::remove(from, rm_ec);
        if (rm_ec) {
            std::fprintf(stderr, "[PluginPendingUpdates] remove_pending_failed: %s (%s)\n",
                         from.string().c_str(), rm_ec.message().c_str());
        }
        return true;
    }

    // Last resort: overwrite dest in place from the completed temp (dest stays intact on failure).
    ec.clear();
    std::filesystem::copy_file(tmp, to, std::filesystem::copy_options::overwrite_existing, ec);
    std::error_code rm_tmp;
    std::filesystem::remove(tmp, rm_tmp);
    if (ec) {
        std::fprintf(stderr, "[PluginPendingUpdates] apply_failed: %s -> %s (%s)\n", from.string().c_str(),
                     to.string().c_str(), ec.message().c_str());
        // Leave pending file for retry; do not delete working module.
        return false;
    }

    std::error_code rm_from;
    std::filesystem::remove(from, rm_from);
    if (rm_from) {
        std::fprintf(stderr, "[PluginPendingUpdates] remove_pending_failed: %s (%s)\n", from.string().c_str(),
                     rm_from.message().c_str());
    }
    return true;
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
        // Ignore our own staging temps if a prior attempt left one behind.
        const auto name = from.filename().string();
        if (name.find(".ds_pending_tmp_") != std::string::npos) {
            continue;
        }
        const auto to = plugins_dir / from.filename();
        if (apply_one(from, to)) {
            ++applied;
            std::fprintf(stderr, "[PluginPendingUpdates] applied: %s\n", to.string().c_str());
        }
    }
    return applied;
}

} // namespace ds::plugin
