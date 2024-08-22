#ifdef _WIN32
#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")
#else

#include <unistd.h>
#include <dlfcn.h>

#endif

#include <filesystem>
#include "platform.hpp"

std::filesystem::path getExePath() {
    static std::filesystem::path p = [] {
#ifdef _WIN32
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, 255);
#else
        char path[1024];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        path[len == -1 ? 0 : len] = 0;
#endif
        return std::filesystem::path{path};
    }();
    return p;
}

module_handler_t loadlib(const char *name) {
    if (!std::filesystem::exists(name)) {
        std::filesystem::path path;
        if (auto p = getExePath().parent_path() / name; std::filesystem::exists(p))
            path = p;
        else if (auto p = std::filesystem::current_path() / name; std::filesystem::exists(p))
            path = p;
#if defined(__linux__)
        else if (auto p = getExePath().parent_path() / "lib"/ name; std::filesystem::exists(p))
            path = p;
        else if (auto p = std::filesystem::current_path() / "lib" /name; std::filesystem::exists(p))
            path = p;
#endif
        if (!path.empty())
            return loadlib(path.string().c_str());
    }
    return
#ifdef _WIN32
        LoadLibraryA(name);
#else
            dlopen(name, RTLD_NOW);
#endif
}

void *loadlibproc(module_handler_t h, const char *name) {
    return
#ifdef _WIN32
        GetProcAddress((HMODULE)h, name);
#else
            dlsym(h, name);
#endif
}

void unloadlib(module_handler_t h) {
    if (!h) return;
#ifdef _WIN32
    FreeLibrary((HMODULE)h);
#else
    dlclose(h);
#endif
}

#include <fstream>
#include <iostream>
#include <string>
#include <array>
#include <cstdio>
#include <charconv>

#ifdef _WIN32
static std::string exec(const char *cmd) {
    std::array<char, 128> buffer;
    std::string result;
#define popen _popen
#define pclose _pclose
    std::shared_ptr<FILE> pipe(_popen(cmd, "r"), _pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}
static std::string WStringToString(const std::wstring_view &wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int) wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int) wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}
static std::string GetCommandLineByPid(DWORD processId) {

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        HMODULE hMod;
        DWORD cbNeeded;

        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) == 0) {
            PEB peb;
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead) && bytesRead == sizeof(peb)) {
                RTL_USER_PROCESS_PARAMETERS upp;
                if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead) && bytesRead == sizeof(upp)) {
                    std::vector<WCHAR> cmdLineBuffer(upp.CommandLine.Length / sizeof(WCHAR));
                    if (ReadProcessMemory(hProcess, upp.CommandLine.Buffer, cmdLineBuffer.data(), upp.CommandLine.Length, &bytesRead) && bytesRead == upp.CommandLine.Length) {
                        return WStringToString({cmdLineBuffer.begin(), cmdLineBuffer.end()});
                    }
                }
            }
        }

        CloseHandle(hProcess);
    }
    
    return {};
}

uintptr_t getParentId() {
    HANDLE hProcess = GetCurrentProcess();
    struct MY_PROCESS_BASIC_INFORMATION {
        NTSTATUS ExitStatus;
        PPEB PebBaseAddress;
        ULONG_PTR AffinityMask;
        KPRIORITY BasePriority;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR InheritedFromUniqueProcessId;
    };
    static_assert(sizeof(MY_PROCESS_BASIC_INFORMATION) == sizeof(PROCESS_BASIC_INFORMATION));

    MY_PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) == 0) {
        return pbi.InheritedFromUniqueProcessId;
    }
    return 0;
}

#else
uintptr_t getParentId() {
    return getppid();
}
#endif

std::string get_cwd(uintptr_t pid) {
#ifdef _WIN32
    if (pid == 0)
        return GetCommandLineA();
    else {
        return GetCommandLineByPid(pid);
    }
#else
    auto param = pid == 0 ? std::string("/proc/self/cmdline") : "/proc/" + std::to_string(pid) + "/cmdline";
    static auto cmd = [](const char* p) {
        std::ifstream file(p);
        std::string cmd;
        std::string cmdline;
        while (std::getline(file, cmdline, '\0')) {
            cmd += cmdline + " ";
        }
        cmd.pop_back();
        return cmd;
    }(param.c_str());
    return cmd.c_str();
#endif
}

std::vector<std::string> get_cwds(uintptr_t pid) {
    std::vector<std::string> cmds;
#ifdef _WIN32
    auto cmd = get_cwd(pid);
    int n = 0;
    if (auto argv = CommandLineToArgvW(std::filesystem::path(cmd).wstring().c_str(), &n); argv) {
        cmds.resize(n);
        for (int i = 0; i < n; i++) {
           cmds[i] = std::filesystem::path(argv[i]).string();
        }
    }
    return cmds;
#else
    auto param = pid == 0 ? std::string("/proc/self/cmdline") : "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream file(param.c_str());
    std::string cmd;
    std::string cmdline;
    while (std::getline(file, cmdline, '\0')) {
        cmds.push_back(cmdline);
    }
#endif
    return cmds;
}

void set_worker_directory(const char *path) {
#ifdef _WIN32
    SetCurrentDirectoryA(path);
#else
    chdir(path);
#endif
}
