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
        if (auto p = getExePath().parent_path() / name; std::filesystem::exists(p))
            return loadlib(p.string().c_str());
        if (auto p = std::filesystem::current_path() / name; std::filesystem::exists(p))
            return loadlib(p.string().c_str());
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

const char *get_cwd() {
#ifdef _WIN32
    return GetCommandLineA();
#else
    static auto cmd = []() {
        std::ifstream file("/proc/self/cmdline");
        std::string cmd;
        std::string cmdline;
        while (std::getline(file, cmdline, '\0')) {
            cmd += cmdline + " ";
        }
        cmd.pop_back();
        return cmd;
    }();
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
