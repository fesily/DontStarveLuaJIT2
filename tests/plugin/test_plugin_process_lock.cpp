// Cross-process lock over a shared plugins tree (client + Master/Caves shards).
// Covers: in-process exclusion, bounded wait, holder stamp, Unavailable reporting,
// and real exclusion against a second OS process (spawns itself in --hold-lock mode).
#include "core/PluginProcessLock.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>

// The one protocol target of the suite: it keeps its own main because --hold-lock
// is a child-process protocol that must run before doctest interprets the command
// line, and the parent needs argv[0] to re-spawn itself. Linking the shared
// ds_test_doctest runner is therefore not possible here.
#define DOCTEST_CONFIG_IMPLEMENT
#include <doctest/doctest.h>

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

// argv[0] as handed to the parent mode, captured before doctest consumes the
// command line; the cross-process case re-spawns this same executable with it.
static std::string g_argv0;

TEST_CASE("test_plugin_process_lock/same_process_exclusion") {
    const auto dir = temp_dir("ds_lock_same");
    PluginProcessLock a;
    PluginProcessLock b;
    std::string err;
    std::string holder;
    REQUIRE_EQ(a.acquire(dir, 0, &err, &holder), LockResult::Acquired);
    REQUIRE(a.held());

    err.clear();
    REQUIRE_EQ(b.acquire(dir, 0, &err, &holder), LockResult::Busy);
    REQUIRE_FALSE(b.held());
    REQUIRE_FALSE(err.empty());

    const auto path = plugin_update_lock_path(dir);
    REQUIRE(fs::exists(path)); // file exists while held
    a.release();
    REQUIRE_FALSE(a.held());
    REQUIRE(fs::exists(path)); // and is never deleted (deleting it would break exclusion)

    err.clear();
    REQUIRE_EQ(b.acquire(dir, 500, &err, &holder), LockResult::Acquired);
    b.release();
}

TEST_CASE("test_plugin_process_lock/bounded_wait") {
    const auto dir = temp_dir("ds_lock_wait");
    PluginProcessLock a;
    PluginProcessLock b;
    std::string err;
    std::string holder;
    REQUIRE_EQ(a.acquire(dir, 0, &err, &holder), LockResult::Acquired);

    const auto t0 = now_ms();
    REQUIRE_EQ(b.acquire(dir, 400, &err, &holder), LockResult::Busy);
    const auto waited = now_ms() - t0;
    REQUIRE_GE(waited, 300); // honored the timeout instead of giving up instantly
    REQUIRE_LT(waited, 5000);

    // A zero-timeout attempt must not spin: it returns immediately-ish.
    const auto t1 = now_ms();
    REQUIRE_EQ(b.acquire(dir, 0, &err, &holder), LockResult::Busy);
    REQUIRE_LT(now_ms() - t1, 500);
    a.release();
    printf("PASS: bounded_wait (%lld ms)\n", static_cast<long long>(waited));
}

TEST_CASE("test_plugin_process_lock/holder_stamp_reported") {
    const auto dir = temp_dir("ds_lock_stamp");
    PluginProcessLock a;
    PluginProcessLock b;
    std::string err;
    std::string holder;
    REQUIRE_EQ(a.acquire(dir, 0, &err, &holder), LockResult::Acquired);
    REQUIRE_EQ(b.acquire(dir, 0, &err, &holder), LockResult::Busy);
    REQUIRE_NE(holder.find("pid="), std::string::npos);
    a.release();
    printf("PASS: holder_stamp (%s)\n", holder.c_str());
}

TEST_CASE("test_plugin_process_lock/unavailable_reported") {
    // Missing directory: the lock file cannot be created -> Unavailable, not Busy.
    const auto missing = fs::temp_directory_path() / "ds_lock_missing_dir_xyz";
    std::error_code ec;
    fs::remove_all(missing, ec);
    PluginProcessLock lock;
    std::string err;
    std::string holder;
    REQUIRE_EQ(lock.acquire(missing, 0, &err, &holder), LockResult::Unavailable);
    REQUIRE_FALSE(err.empty());
    REQUIRE_FALSE(lock.held());
}

TEST_CASE("test_plugin_process_lock/cross_process_exclusion") {
    const auto dir = temp_dir("ds_lock_child");
    const auto ready = dir / "child_ready";
    const auto exe = fs::absolute(g_argv0).string();
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
    // jthread, so a REQUIRE that throws above the explicit join() still joins on
    // unwind; a destroyed joinable std::thread would std::terminate the run.
    std::jthread child([&cmd, &child_status] { child_status = std::system(cmd.c_str()); });

    bool saw_ready = false;
    for (int i = 0; i < 500; ++i) {
        if (fs::exists(ready)) {
            saw_ready = true;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(saw_ready); // child holds the lock now

    PluginProcessLock lock;
    std::string err;
    std::string holder;
    REQUIRE_EQ(lock.acquire(dir, 0, &err, &holder), LockResult::Busy);
    REQUIRE_NE(holder.find("pid="), std::string::npos); // stamp from the other process

    // Child exits after ~1500 ms; waiting acquire must succeed afterwards.
    err.clear();
    REQUIRE_EQ(lock.acquire(dir, 15000, &err, &holder), LockResult::Acquired);
    lock.release();
    child.join();
    REQUIRE_EQ(child_status, 0); // child acquired, held and released cleanly
}

int main(int argc, char **argv) {
    // Child protocol first: it must not go through doctest's command line at all.
    if (argc >= 4 && std::string(argv[1]) == "--hold-lock") {
        return child_hold(fs::path(argv[2]), std::atoi(argv[3]));
    }

    g_argv0 = argc > 0 ? argv[0] : "";
    doctest::Context context;
    context.setOption("no-breaks", true);
    context.applyCommandLine(argc, argv);
    return context.run();
}
