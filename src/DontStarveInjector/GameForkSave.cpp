#include "config.hpp"
#include <spdlog/spdlog.h>
#include <atomic>

#ifdef _WIN32
#include <Windows.h>
#include <winternl.h>
#endif

#ifdef __linux__
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <cerrno>

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

#ifdef _WIN32

#ifndef STATUS_PROCESS_CLONED
#define STATUS_PROCESS_CLONED static_cast<NTSTATUS>(0x00000129L)
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED
#define RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED 0x00000001UL
#endif

#ifndef RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES
#define RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES 0x00000002UL
#endif

typedef struct _RTL_USER_PROCESS_INFORMATION {
    ULONG Length;
    HANDLE Process;
    HANDLE Thread;
    CLIENT_ID ClientId;
    SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

using RtlCloneUserProcessFn = NTSTATUS(NTAPI *)(
        ULONG,
        PSECURITY_DESCRIPTOR,
        PSECURITY_DESCRIPTOR,
        HANDLE,
        PRTL_USER_PROCESS_INFORMATION);
using NtTerminateProcessFn = NTSTATUS(NTAPI *)(HANDLE, NTSTATUS);

struct WinCloneApi {
    RtlCloneUserProcessFn clone{nullptr};
    NtTerminateProcessFn terminate{nullptr};
    bool ready{false};
};

static WinCloneApi load_clone_api() {
    WinCloneApi api;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        return api;
    }

    api.clone = reinterpret_cast<RtlCloneUserProcessFn>(GetProcAddress(ntdll, "RtlCloneUserProcess"));
    api.terminate = reinterpret_cast<NtTerminateProcessFn>(GetProcAddress(ntdll, "NtTerminateProcess"));
    api.ready = api.clone != nullptr && api.terminate != nullptr;
    return api;
}

static WinCloneApi& clone_api() {
    static WinCloneApi api = load_clone_api();
    return api;
}

static std::atomic<HANDLE> g_save_child_handle{nullptr};

static void close_child_handle(HANDLE handle) {
    if (handle != nullptr) {
        CloseHandle(handle);
    }
}

static void reap_children() {
    HANDLE expected = g_save_child_handle.load();
    if (expected == nullptr) {
        return;
    }

    const DWORD wait_result = WaitForSingleObject(expected, 0);
    if (wait_result == WAIT_OBJECT_0) {
        DWORD exit_code = STILL_ACTIVE;
        if (GetExitCodeProcess(expected, &exit_code) != 0) {
            spdlog::info("[fork_save] child {} exited with status {}",
                         static_cast<const void*>(expected),
                         exit_code);
        }
        close_child_handle(expected);
        g_save_child_handle.store(nullptr);
    }
}

static void wait_for_previous_save() {
    HANDLE expected = g_save_child_handle.load();
    if (expected == nullptr) {
        return;
    }

    spdlog::info("[fork_save] waiting for previous save child {}", static_cast<const void*>(expected));
    WaitForSingleObject(expected, INFINITE);
    close_child_handle(expected);
    g_save_child_handle.store(nullptr);
}

#endif

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
#elif defined(_WIN32)
    auto& api = clone_api();
    if (!api.ready) {
        spdlog::warn("[fork_save] Windows clone API is unavailable");
        return "unsupported";
    }

    reap_children();
    wait_for_previous_save();

    RTL_USER_PROCESS_INFORMATION process_info{};
    process_info.Length = sizeof(process_info);
    const NTSTATUS status = api.clone(
            RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
            nullptr,
            nullptr,
            nullptr,
            &process_info);

    if (status == STATUS_PROCESS_CLONED) {
        return "child";
    }

    if (status != STATUS_SUCCESS) {
        spdlog::error("[fork_save] RtlCloneUserProcess failed: 0x{:08x}", static_cast<unsigned long>(status));
        return "error";
    }

    if (process_info.Thread != nullptr) {
        ResumeThread(process_info.Thread);
        CloseHandle(process_info.Thread);
    }
    g_save_child_handle.store(process_info.Process);
    spdlog::info("[fork_save] forked child {} for save", static_cast<const void*>(process_info.Process));
    return "parent";
#else
    return "unsupported";
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_fork_save_exit() {
#ifdef __linux__
    spdlog::info("[fork_save] child save complete, exiting");
    _exit(0);
#elif defined(_WIN32)
    auto& api = clone_api();
    if (!api.ready) {
        return;
    }

    spdlog::info("[fork_save] child save complete, exiting");
    api.terminate(GetCurrentProcess(), STATUS_SUCCESS);
#endif
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_fork_save_cleanup() {
#ifdef __linux__
    reap_children();
#elif defined(_WIN32)
    reap_children();
#endif
}
