// L0 cross-process lock over a shared plugins tree (see header).
#include "PluginProcessLock.hpp"

#include <chrono>
#include <cstdio>
#include <thread>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace ds::plugin {
namespace {

constexpr int kPollIntervalMs = 100;
// Only byte 0 is locked (Windows byte-range locks also block reads of the locked
// range by other handles), so the diagnostics stamp lives further in the file.
constexpr unsigned long kLockedByteCount = 1;
constexpr size_t kStampOffset = 64;
constexpr size_t kMaxStampBytes = 96;

enum class LockTry { Acquired, Busy, OpenFailed };

std::string host_name() {
    char name[64] = {};
#if defined(_WIN32)
    DWORD n = sizeof(name);
    if (!GetComputerNameA(name, &n)) {
        name[0] = '\0';
    }
#else
    if (::gethostname(name, sizeof(name) - 1) != 0) {
        name[0] = '\0';
    }
#endif
    return std::string(name);
}

std::string host_stamp() {
#if defined(_WIN32)
    const unsigned long pid = static_cast<unsigned long>(GetCurrentProcessId());
#else
    const unsigned long pid = static_cast<unsigned long>(::getpid());
#endif
    char buf[kMaxStampBytes] = {};
    std::snprintf(buf, sizeof(buf), "pid=%lu host=%s", pid, host_name().c_str());
    return std::string(buf);
}

// handle: Windows file handle (null on POSIX). fd: POSIX fd (< 0 on Windows).
void write_stamp(void *handle, int fd) {
    const std::string stamp = host_stamp();
#if defined(_WIN32)
    (void)fd;
    auto *h = static_cast<HANDLE>(handle);
    if (h == nullptr || h == INVALID_HANDLE_VALUE) {
        return;
    }
    LARGE_INTEGER off{};
    off.QuadPart = static_cast<LONGLONG>(kStampOffset);
    if (!SetFilePointerEx(h, off, nullptr, FILE_BEGIN)) {
        return;
    }
    DWORD written = 0;
    (void)WriteFile(h, stamp.data(), static_cast<DWORD>(stamp.size()), &written, nullptr);
    (void)FlushFileBuffers(h);
#else
    (void)handle;
    if (fd < 0) {
        return;
    }
    const ssize_t ignored = ::pwrite(fd, stamp.data(), stamp.size(), kStampOffset);
    (void)ignored;
#endif
}

// Best-effort read of the holder stamp; never throws, never blocks.
std::string read_stamp(const std::filesystem::path &path) {
    std::string out;
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size <= kStampOffset || size > 4096) {
        return out;
    }
#if defined(_WIN32)
    HANDLE h = CreateFileW(path.wstring().c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return out;
    }
    LARGE_INTEGER off{};
    off.QuadPart = static_cast<LONGLONG>(kStampOffset);
    char buf[kMaxStampBytes] = {};
    DWORD got = 0;
    if (SetFilePointerEx(h, off, nullptr, FILE_BEGIN) && ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr)) {
        out.assign(buf, got);
    }
    CloseHandle(h);
#else
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) {
        return out;
    }
    char buf[kMaxStampBytes] = {};
    const ssize_t got = ::pread(fd, buf, sizeof(buf) - 1, kStampOffset);
    if (got > 0) {
        out.assign(buf, static_cast<size_t>(got));
    }
    ::close(fd);
#endif
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r' || out.back() == '\0')) {
        out.pop_back();
    }
    return out;
}

LockTry try_lock_once(const std::filesystem::path &path, void **out_handle, int *out_fd,
                      std::string *open_err) {
#if defined(_WIN32)
    HANDLE h = CreateFileW(path.wstring().c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (open_err) {
            *open_err = "cannot open lock file: " + path.generic_string();
        }
        return LockTry::OpenFailed;
    }
    OVERLAPPED ov{};
    if (!LockFileEx(h, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, kLockedByteCount, 0,
                    &ov)) {
        CloseHandle(h);
        return LockTry::Busy;
    }
    *out_handle = h;
    write_stamp(h, -1);
    return LockTry::Acquired;
#else
    (void)out_handle;
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0666);
    if (fd < 0) {
        if (open_err) {
            *open_err = "cannot open lock file: " + path.generic_string() + " (" +
                        std::strerror(errno) + ")";
        }
        return LockTry::OpenFailed;
    }
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(fd);
        return errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR ? LockTry::Busy
                                                                        : LockTry::OpenFailed;
    }
    *out_fd = fd;
    write_stamp(nullptr, fd);
    return LockTry::Acquired;
#endif
}

} // namespace

std::filesystem::path plugin_update_lock_path(const std::filesystem::path &plugins_dir) {
    if (plugins_dir.empty()) {
        return {};
    }
    return plugins_dir / ".ds_plugin_update.lock";
}

PluginProcessLock::PluginProcessLock() = default;

PluginProcessLock::~PluginProcessLock() { release(); }

LockResult PluginProcessLock::acquire(const std::filesystem::path &plugins_dir, int timeout_ms,
                                      std::string *err, std::string *holder_info) {
    release();
    path_ = plugin_update_lock_path(plugins_dir);
    if (path_.empty()) {
        if (err) {
            *err = "plugin update lock: empty plugins dir";
        }
        return LockResult::Unavailable;
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms > 0 ? timeout_ms : 0);
    for (;;) {
        void *handle = nullptr;
        int fd = -1;
        std::string open_err;
        switch (try_lock_once(path_, &handle, &fd, &open_err)) {
        case LockTry::Acquired:
#if defined(_WIN32)
            handle_ = handle;
#else
            fd_ = fd;
#endif
            return LockResult::Acquired;
        case LockTry::OpenFailed:
            // Retrying cannot help (missing dir / bad permissions / unsupported locking).
            if (err) {
                *err = open_err.empty() ? "plugin update lock unavailable" : open_err;
            }
            return LockResult::Unavailable;
        case LockTry::Busy:
            break;
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            if (err) {
                *err = "another process is updating this plugins dir";
            }
            if (holder_info) {
                *holder_info = read_stamp(path_);
            }
            return LockResult::Busy;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(kPollIntervalMs));
    }
}

void PluginProcessLock::release() {
    if (!held()) {
        return;
    }
#if defined(_WIN32)
    auto *h = static_cast<HANDLE>(handle_);
    OVERLAPPED ov{};
    (void)UnlockFileEx(h, 0, kLockedByteCount, 0, &ov);
    CloseHandle(h);
    handle_ = nullptr;
#else
    (void)::flock(fd_, LOCK_UN);
    ::close(fd_);
    fd_ = -1;
#endif
}

} // namespace ds::plugin
