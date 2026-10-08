#include "PluginPendingUpdates.hpp"

#include "PluginProcessLock.hpp"

#include <cstdio>
#include <cstring>
#include <system_error>
#include <vector>

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

// Shared plugins tree: another process may be mid-apply (plugin.manager) or
// moving its own pending set. Wait briefly, then defer to the next inject —
// pending files stay, so nothing is lost.
constexpr int kPendingMoveLockTimeoutMs = 5000;

// Stem of a legacy flat pending module/meta name at the pending root, else "".
std::string flat_pending_stem(const std::string &name) {
    if (!name.starts_with("plugin_")) {
        return {};
    }
    const char *exts[] = {".dll", ".so", ".dylib", ".meta.json"};
    for (const char *ext : exts) {
        if (name.ends_with(ext)) {
            const std::string stem = name.substr(0, name.size() - std::strlen(ext));
            // plugin_x.meta.json -> stem from the module form
            return stem.ends_with(".meta") ? stem.substr(0, stem.size() - std::strlen(".meta"))
                                           : stem;
        }
    }
    return {};
}

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
    // Package members land in <plugins>/<package>/…: make the parent exist first
    // (rename/copy do not create intermediate directories).
    if (!to.parent_path().empty()) {
        std::filesystem::create_directories(to.parent_path(), ec);
        ec.clear();
    }

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

size_t consolidate_flat_plugin_layout(const std::filesystem::path &plugins_dir) {
    std::error_code ec;
    if (plugins_dir.empty() || !std::filesystem::is_directory(plugins_dir, ec)) {
        return 0;
    }

    PluginProcessLock tree_lock;
    std::string lock_err;
    std::string holder;
    const auto lock_state =
        tree_lock.acquire(plugins_dir, kPendingMoveLockTimeoutMs, &lock_err, &holder);
    if (lock_state == LockResult::Busy) {
        return 0; // another process is mutating the tree; next boot cleans up
    }

    // Collect first, remove after: deleting entries while iterating a directory can
    // skip the following entry (Windows FindNextFile).
    std::vector<std::filesystem::path> doomed;
#if defined(_WIN32)
    const char *module_exts[] = {".dll", ".so", ".dylib"};
#else
    const char *module_exts[] = {".so", ".dylib", ".dll"};
#endif
    // NOTE: per-entry error_code — never reuse the iterator's (a missing candidate path
    // sets it and would abort the walk).
    for (std::filesystem::directory_iterator it(plugins_dir, ec), end; it != end;
         it.increment(ec)) {
        if (ec) {
            break;
        }
        std::error_code probe_ec;
        if (!it->is_regular_file(probe_ec)) {
            continue;
        }
        const std::string name = it->path().filename().string();
        if (!name.starts_with("plugin_")) {
            continue;
        }
        // Stem + suffix pairs that belong to a flat install.
        std::string stem;
        for (const char *ext : module_exts) {
            if (name.ends_with(ext)) {
                stem = name.substr(0, name.size() - std::strlen(ext));
                break;
            }
        }
        if (stem.empty() && name.ends_with(".meta.json")) {
            stem = name.substr(0, name.size() - std::strlen(".meta.json"));
        }
        if (stem.empty()) {
            continue;
        }
        // Flat modules are unsupported now: a matching package dir makes the flat copy a
        // stale leftover (safe to delete); without one, keep the file but warn once.
        bool packaged = false;
        for (const char *ext : module_exts) {
            std::error_code cand_ec;
            if (std::filesystem::is_regular_file(plugins_dir / stem / (stem + ext), cand_ec)) {
                packaged = true;
                break;
            }
        }
        if (!packaged) {
            std::fprintf(stderr,
                         "[PluginPendingUpdates] unsupported flat %s: plugins must live in "
                         "plugins/<stem>/<stem>%s\n",
                         it->path().string().c_str(), module_exts[0]);
            continue;
        }
        doomed.push_back(it->path());
    }

    size_t removed = 0;
    for (const auto &path : doomed) {
        std::error_code rm_ec;
        std::filesystem::remove(path, rm_ec);
        if (rm_ec) {
            continue; // loaded/locked module: the loader preference covers this boot
        }
        ++removed;
        std::fprintf(stderr, "[PluginPendingUpdates] removed shadowed flat %s\n",
                     path.string().c_str());
    }
    return removed;
}

size_t apply_pending_plugin_updates(const std::filesystem::path &plugins_dir) {
    const auto pending_dir = plugins_dir / "update_pending";
    std::error_code ec;
    if (!std::filesystem::is_directory(pending_dir, ec)) {
        return 0;
    }

    // Serialize with any other process mutating this shared tree (see header).
    PluginProcessLock tree_lock;
    std::string lock_err;
    std::string holder;
    const auto lock_state =
        tree_lock.acquire(plugins_dir, kPendingMoveLockTimeoutMs, &lock_err, &holder);
    if (lock_state == LockResult::Busy) {
        std::string detail = lock_err;
        if (!holder.empty()) {
            detail += " [" + holder + "]";
        }
        std::fprintf(stderr,
                     "[PluginPendingUpdates] deferred: %s; pending files kept for the next inject\n",
                     detail.c_str());
        return 0;
    }
    if (lock_state == LockResult::Unavailable) {
        // No usable exclusive locking (odd filesystem/permissions): keep the legacy
        // behavior — moves are rename-atomic and fail soft per file.
        std::fprintf(stderr,
                     "[PluginPendingUpdates] note: %s; applying without cross-process exclusion\n",
                     lock_err.c_str());
    }

    // Pending mirrors the install layout: package members under
    // update_pending/<package>/. Walk recursively and rebuild the same relative path
    // inside plugins_dir (legacy flat members are routed into their package dir below).
    std::vector<std::filesystem::path> pending_files;
    for (std::filesystem::recursive_directory_iterator it(pending_dir, ec), end;
         it != end && !ec; it.increment(ec)) {
        std::error_code probe_ec;
        if (!it->is_regular_file(probe_ec)) {
            continue;
        }
        const auto name = it->path().filename().string();
        if (name.find(".ds_pending_tmp_") != std::string::npos) {
            continue; // our own staging leftover
        }
        pending_files.push_back(it->path());
    }

    size_t applied = 0;
    for (const auto &from : pending_files) {
        std::error_code rel_ec;
        const auto rel = std::filesystem::relative(from, pending_dir, rel_ec);
        if (rel_ec || rel.empty() || rel.string().starts_with("..")) {
            continue; // outside the pending root (should not happen)
        }
        // Legacy flat pending member (written by an old flat install): route it into the
        // package dir, which is the only supported layout now.
        auto dest_rel = rel;
        if (rel.parent_path().empty()) {
            const std::string stem = flat_pending_stem(rel.filename().string());
            if (stem.empty()) {
                std::fprintf(stderr,
                             "[PluginPendingUpdates] ignoring unsupported flat pending member %s "
                             "(plugins must live in plugins/<stem>/)\n",
                             rel.string().c_str());
                continue;
            }
            dest_rel = std::filesystem::path(stem) / rel.filename();
        }
        const auto to = plugins_dir / dest_rel;
        if (apply_one(from, to)) {
            ++applied;
            std::fprintf(stderr, "[PluginPendingUpdates] applied: %s\n", to.string().c_str());
        }
    }
    return applied;
}

} // namespace ds::plugin
