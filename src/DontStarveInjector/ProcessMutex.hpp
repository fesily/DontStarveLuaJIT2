#ifndef PROCESS_MUTEX_H
#define PROCESS_MUTEX_H

#include <string>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#else
#include <semaphore.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#endif

class ProcessMutex {
public:
    // 构造函数，name 是互斥锁的全局名称
    ProcessMutex(const std::string &name) {
#ifdef _WIN32
        // Windows: 创建或打开命名互斥锁
        mutex_ = CreateMutexA(NULL, FALSE, name.c_str());
        if (mutex_ == NULL) {
            throw std::runtime_error("Failed to create mutex: " + std::to_string(GetLastError()));
        }
#else
        // POSIX: 创建或打开命名信号量
        lockFilePath_ = "/tmp/" + name + ".lock";
        fd_ = open(lockFilePath_.c_str(), O_CREAT | O_RDWR, 0644);
        if (fd_ == -1) {
            throw std::runtime_error("Failed to open lock file: " + std::string(strerror(errno)));
        }
#endif
    }

    // 析构函数，释放资源
    ~ProcessMutex() {
#ifdef _WIN32
        if (mutex_ != NULL) {
            CloseHandle(mutex_);
        }
#else
        if (fd_ != -1) {
            close(fd_);
        }
#endif
    }

    // 加锁，阻塞直到获取锁
    void lock() {
#ifdef _WIN32
        DWORD result = WaitForSingleObject(mutex_, INFINITE);
        if (result != WAIT_OBJECT_0) {
            throw std::runtime_error("Failed to lock mutex: " + std::to_string(GetLastError()));
        }
#else
        struct flock fl;
        fl.l_type = F_WRLCK;  // 写锁
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;  // 锁定整个文件

        // 尝试加锁，阻塞等待
        if (fcntl(fd_, F_SETLKW, &fl) == -1) {
            throw std::runtime_error("Failed to lock file: " + std::string(strerror(errno)));
        }
#endif
    }

    // 尝试加锁，非阻塞
    bool try_lock() {
#ifdef _WIN32
        DWORD result = WaitForSingleObject(mutex_, 0);
        if (result == WAIT_OBJECT_0) {
            return true;
        } else if (result == WAIT_TIMEOUT) {
            return false;
        } else {
            throw std::runtime_error("Failed to try lock mutex: " + std::to_string(GetLastError()));
        }
#else
        struct flock fl;
        fl.l_type = F_WRLCK;  // 写锁
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;  // 锁定整个文件

        // 尝试加锁，非阻塞
        if (fcntl(fd_, F_SETLK, &fl) == -1) {
            if (errno == EACCES || errno == EAGAIN) {
                return false;  // 锁已被其他进程持有
            } else {
                throw std::runtime_error("Failed to try lock file: " + std::string(strerror(errno)));
            }
        }
        return true;
#endif
    }

    // 解锁
    void unlock() {
#ifdef _WIN32
        if (!ReleaseMutex(mutex_)) {
            throw std::runtime_error("Failed to unlock mutex: " + std::to_string(GetLastError()));
        }
#else
        struct flock fl;
        fl.l_type = F_UNLCK;  // 解锁
        fl.l_whence = SEEK_SET;
        fl.l_start = 0;
        fl.l_len = 0;  // 解锁整个文件

        if (fcntl(fd_, F_SETLK, &fl) == -1) {
            throw std::runtime_error("Failed to unlock file: " + std::string(strerror(errno)));
        }
#endif
    }

    // 禁止拷贝和移动
    ProcessMutex(const ProcessMutex &) = delete;
    ProcessMutex &operator=(const ProcessMutex &) = delete;
    ProcessMutex(ProcessMutex &&) = delete;
    ProcessMutex &operator=(ProcessMutex &&) = delete;

private:
#ifdef _WIN32
    HANDLE mutex_;
#else
    std::string lockFilePath_;
    int fd_;
#endif
};

#endif// PROCESS_MUTEX_H