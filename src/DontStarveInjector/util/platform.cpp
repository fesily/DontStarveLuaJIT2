#ifdef _WIN32
#include <Windows.h>
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

static std::string exec(const char *cmd) {
    std::array<char, 128> buffer;
    std::string result;
#ifdef _WIN32
#define popen _popen
#define pclose _pclose
#endif
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}

uintptr_t getParentId() {
    const auto pid = GetCurrentProcessId();
    std::string command = "wmic process where processid=\"" + std::to_string(pid) + "\" get parentprocessid";
    std::string output = exec(command.c_str());
    output = output.substr(output.find('\n') + 1);
    uintptr_t parentPid = 0;
    std::from_chars(output.c_str(), output.data() + output.size(), parentPid);
    return parentPid;
}

static std::string getCommandLineForProcess(uintptr_t pid) {
    std::string command = "wmic process where processid=\"" + std::to_string(pid) + "\" get CommandLine";
    std::string output = exec(command.c_str());
    return output;
}

const char *get_cwd(uintptr_t pid) {
#ifdef _WIN32
    if (pid == 0)
        return GetCommandLineA();
    else {
        const auto pid = getParentId();
        static auto parentCmd = getCommandLineForProcess(pid);
        return parentCmd.c_str();
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

void set_worker_directory(const char *path) {
#ifdef _WIN32
    SetCurrentDirectoryA(path);
#else
    chdir(path);
#endif
}
