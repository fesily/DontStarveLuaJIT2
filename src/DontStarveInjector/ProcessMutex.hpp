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
    ProcessMutex(const std::string& name) {
#ifdef _WIN32
        // Windows: 创建或打开命名互斥锁
        mutex_ = CreateMutexA(NULL, FALSE, name.c_str());
        if (mutex_ == NULL) {
            throw std::runtime_error("Failed to create mutex: " + std::to_string(GetLastError()));
        }
#else
        // POSIX: 创建或打开命名信号量
        semaphore_ = sem_open(name.c_str(), O_CREAT, 0644, 1);
        if (semaphore_ == SEM_FAILED) {
            throw std::runtime_error("Failed to create semaphore: " + std::string(strerror(errno)));
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
        if (semaphore_ != SEM_FAILED) {
            sem_close(semaphore_);
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
        if (sem_wait(semaphore_) != 0) {
            throw std::runtime_error("Failed to lock semaphore: " + std::string(strerror(errno)));
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
        if (sem_trywait(semaphore_) == 0) {
            return true;
        } else if (errno == EAGAIN) {
            return false;
        } else {
            throw std::runtime_error("Failed to try lock semaphore: " + std::string(strerror(errno)));
        }
#endif
    }

    // 解锁
    void unlock() {
#ifdef _WIN32
        if (!ReleaseMutex(mutex_)) {
            throw std::runtime_error("Failed to unlock mutex: " + std::to_string(GetLastError()));
        }
#else
        if (sem_post(semaphore_) != 0) {
            throw std::runtime_error("Failed to unlock semaphore: " + std::string(strerror(errno)));
        }
#endif
    }

    // 禁止拷贝和移动
    ProcessMutex(const ProcessMutex&) = delete;
    ProcessMutex& operator=(const ProcessMutex&) = delete;
    ProcessMutex(ProcessMutex&&) = delete;
    ProcessMutex& operator=(ProcessMutex&&) = delete;

private:
#ifdef _WIN32
    HANDLE mutex_;
#else
    sem_t* semaphore_;
#endif
};

#endif // PROCESS_MUTEX_H