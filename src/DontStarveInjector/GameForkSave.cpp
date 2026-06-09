#include "config.hpp"
#include <spdlog/spdlog.h>

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>
#include <atomic>

static std::atomic<pid_t> g_save_child_pid{0};

static void reap_children() {
    pid_t expected = g_save_child_pid.load();
    if (expected <= 0) return;

    int status = 0;
    pid_t result = waitpid(expected, &status, WNOHANG);
    if (result == expected) {
        if (WIFEXITED(status)) {
            spdlog::info("[fork_save] child {} exited with status {}", expected, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            spdlog::warn("[fork_save] child {} killed by signal {}", expected, WTERMSIG(status));
        }
        g_save_child_pid.store(0);
    } else if (result == -1 && errno == ECHILD) {
        g_save_child_pid.store(0);
    }
}

static void wait_for_previous_save() {
    pid_t expected = g_save_child_pid.load();
    if (expected <= 0) return;

    spdlog::info("[fork_save] waiting for previous save child {}", expected);
    int status = 0;
    waitpid(expected, &status, 0);
    g_save_child_pid.store(0);
}

#endif // __linux__

DONTSTARVEINJECTOR_GAME_API const char *DS_LUAJIT_fork_save() {
#ifdef __linux__
    reap_children();
    wait_for_previous_save();

    pid_t pid = fork();
    if (pid < 0) {
        spdlog::error("[fork_save] fork() failed: {}", strerror(errno));
        return "error";
    }
    if (pid == 0) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_IGN);
        return "child";
    }
    g_save_child_pid.store(pid);
    spdlog::info("[fork_save] forked child {} for save", pid);
    return "parent";
#else
    return "unsupported";
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_fork_save_exit() {
#ifdef __linux__
    spdlog::info("[fork_save] child save complete, exiting");
    _exit(0);
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_fork_save_cleanup() {
#ifdef __linux__
    reap_children();
#endif
}

