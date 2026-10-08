// Cross-process lock over a shared plugins tree (client + Master/Caves shards).
// Covers: in-process exclusion, bounded wait, holder stamp, Unavailable reporting,
// and real exclusion against a second OS process (spawns itself in --hold-lock mode).
#include "core/PluginProcessLock.hpp"

#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

namespace fs = std::filesystem;
using ds::plugin::LockResult;
using ds::plugin::PluginProcessLock;
using ds::plugin::plugin_update_lock_path;

static fs::path temp_dir(const char *name) {
    auto d = fs::temp_directory_path() / name;
    std::error_code ec;
    fs::remove_all(d, ec);
    fs::create_directories(d, ec);
    return d;
}

// Child keeps the lock this long; parent waits for it via a blocking acquire.
constexpr int kChildHoldMs = 1500;

static long long now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

// Child mode: take the lock, publish a ready marker, hold, release, exit.
static int child_hold(const fs::path &dir, int hold_ms) {
    PluginProcessLock lock;
    std::string err;
    std::string holder;
    if (lock.acquire(dir, 0, &err, &holder) != LockResult::Acquired) {
        std::printf("CHILD: acquire failed: %s\n", err.c_str());
        return 1;
    }
    std::ofstream(dir / "child_ready") << "1";
    std::this_thread::sleep_for(std::chrono::milliseconds(hold_ms));
    lock.release();
    return 0;
}

static void test_same_process_exclusion() {
    const auto dir = temp_dir("ds_lock_same");
    PluginProcessLock a;
    PluginProcessLock b;
    std::string err;
    std::string holder;
    assert(a.acquire(dir, 0, &err, &holder) == LockResult::Acquired);
    assert(a.held());

    err.clear();
    assert(b.acquire(dir, 0, &err, &holder) == LockResult::Busy);
    assert(!b.held());
    assert(!err.empty());

    const auto path = plugin_update_lock_path(dir);
    assert(fs::exists(path)); // file exists while held
    a.release();
    assert(!a.held());
    assert(fs::exists(path)); // and is never deleted (deleting it would break exclusion)

    err.clear();
    assert(b.acquire(dir, 500, &err, &holder) == LockResult::Acquired);
    b.release();
    printf("PASS: same_process_exclusion\n");
}

static void test_bounded_wait() {
    const auto dir = temp_dir("ds_lock_wait");
    PluginProcessLock a;
    PluginProcessLock b;
    std::string err;
    std::string holder;
    assert(a.acquire(dir, 0, &err, &holder) == LockResult::Acquired);

    const auto t0 = now_ms();
    assert(b.acquire(dir, 400, &err, &holder) == LockResult::Busy);
    const auto waited = now_ms() - t0;
    assert(waited >= 300); // honored the timeout instead of giving up instantly
    assert(waited < 5000);

    // A zero-timeout attempt must not spin: it returns immediately-ish.
    const auto t1 = now_ms();
    assert(b.acquire(dir, 0, &err, &holder) == LockResult::Busy);
    assert(now_ms() - t1 < 500);
    a.release();
    printf("PASS: bounded_wait (%lld ms)\n", static_cast<long long>(waited));
}

static void test_holder_stamp_reported() {
    const auto dir = temp_dir("ds_lock_stamp");
    PluginProcessLock a;
    PluginProcessLock b;
    std::string err;
    std::string holder;
    assert(a.acquire(dir, 0, &err, &holder) == LockResult::Acquired);
    assert(b.acquire(dir, 0, &err, &holder) == LockResult::Busy);
    assert(holder.find("pid=") != std::string::npos);
    a.release();
    printf("PASS: holder_stamp (%s)\n", holder.c_str());
}

static void test_unavailable_reported() {
    // Missing directory: the lock file cannot be created -> Unavailable, not Busy.
    const auto missing = fs::temp_directory_path() / "ds_lock_missing_dir_xyz";
    std::error_code ec;
    fs::remove_all(missing, ec);
    PluginProcessLock lock;
    std::string err;
    std::string holder;
    assert(lock.acquire(missing, 0, &err, &holder) == LockResult::Unavailable);
    assert(!err.empty());
    assert(!lock.held());
    printf("PASS: unavailable_reported\n");
}

static void test_cross_process_exclusion(const char *argv0) {
    const auto dir = temp_dir("ds_lock_child");
    const auto ready = dir / "child_ready";
    const auto exe = fs::absolute(argv0).string();
    const std::string args =
        " --hold-lock \"" + dir.string() + "\" " + std::to_string(kChildHoldMs);
#if defined(_WIN32)
    // std::system runs `cmd /c <line>`; with more than two quotes cmd drops the
    // leading and trailing quote, so wrap the whole command once more.
    const std::string cmd = "\"\"" + exe + "\"" + args + "\"";
#else
    const std::string cmd = "\"" + exe + "\"" + args;
#endif
    int child_status = -1;
    std::thread child([&cmd, &child_status] { child_status = std::system(cmd.c_str()); });

    bool saw_ready = false;
    for (int i = 0; i < 500; ++i) {
        if (fs::exists(ready)) {
            saw_ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    assert(saw_ready); // child holds the lock now

    PluginProcessLock lock;
    std::string err;
    std::string holder;
    assert(lock.acquire(dir, 0, &err, &holder) == LockResult::Busy);
    assert(holder.find("pid=") != std::string::npos); // stamp from the other process

    // Child exits after ~1500 ms; waiting acquire must succeed afterwards.
    err.clear();
    assert(lock.acquire(dir, 15000, &err, &holder) == LockResult::Acquired);
    lock.release();
    child.join();
    assert(child_status == 0); // child acquired, held and released cleanly
    printf("PASS: cross_process_exclusion\n");
}

int main(int argc, char **argv) {
    if (argc >= 4 && std::string(argv[1]) == "--hold-lock") {
        return child_hold(fs::path(argv[2]), std::atoi(argv[3]));
    }

    test_same_process_exclusion();
    test_bounded_wait();
    test_holder_stamp_reported();
    test_unavailable_reported();
    test_cross_process_exclusion(argc > 0 ? argv[0] : "");

    printf("ALL PASS plugin_process_lock\n");
    return 0;
}
