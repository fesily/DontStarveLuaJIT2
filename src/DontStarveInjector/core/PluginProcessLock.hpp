#pragma once
// Cross-process exclusive lock over ONE shared plugins tree.
//
// Why: several game processes (client + Master/Caves shards, dedicated + local)
// share the same mod `plugins/` directory. plugin.manager's mutex is per-process,
// so it cannot serialize the two writers of that tree:
//   1. L0 `apply_pending_plugin_updates` (moves update_pending/ into plugins/)
//   2. plugin.manager apply (download → extract → install module/meta files)
// Both take this lock, so only one process mutates the tree at a time.
//
// Lock file: <plugins_dir>/.ds_plugin_update.lock — never deleted by this code.
// Deleting it while another process holds it would let a third process lock a
// fresh file and run concurrently. It is safe to delete manually when no game
// process is running, and it is ignored by the plugin loader / inventory scan.
//
// Advisory: a filesystem without working locking (some network mounts) degrades
// to "no exclusion", never to an error path that blocks boot.

#include "config/InjectorHostConfig.hpp" // DS_INJECTOR_CXX_API

#include <filesystem>
#include <string>

namespace ds::plugin {

// Canonical lock path for a plugins dir (single source of truth: L0 + manager).
DS_INJECTOR_CXX_API std::filesystem::path plugin_update_lock_path(
    const std::filesystem::path &plugins_dir);

enum class LockResult {
    Acquired,    // this object holds the lock
    Busy,        // another process holds it (timeout honored)
    Unavailable, // cannot open/lock the file (missing dir, permissions, no locking support)
};

// Busy vs Unavailable matters: callers defer on Busy (someone is updating right now)
// but fall back to unlocked legacy behavior on Unavailable (locking unsupported).

class PluginProcessLock {
public:
    DS_INJECTOR_CXX_API PluginProcessLock();
    DS_INJECTOR_CXX_API ~PluginProcessLock();
    PluginProcessLock(const PluginProcessLock &) = delete;
    PluginProcessLock &operator=(const PluginProcessLock &) = delete;

    // Try to take the tree lock for up to timeout_ms (0 = a single attempt).
    // On failure sets *err to a short reason and, when another process holds it,
    // *holder_info to that process's stamp ("pid=… host=…") if it could be read.
    DS_INJECTOR_CXX_API LockResult acquire(const std::filesystem::path &plugins_dir, int timeout_ms,
                                          std::string *err, std::string *holder_info);

    // Release if held; safe to call repeatedly. Called by the destructor.
    DS_INJECTOR_CXX_API void release();

    bool held() const {
#if defined(_WIN32)
        return handle_ != nullptr;
#else
        return fd_ >= 0;
#endif
    }

    // Path of the lock file this object used (empty before acquire).
    const std::filesystem::path &path() const { return path_; }

private:
    std::filesystem::path path_;
#if defined(_WIN32)
    void *handle_ = nullptr;
#else
    int fd_ = -1;
#endif
};

} // namespace ds::plugin
