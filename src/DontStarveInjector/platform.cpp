#include "platform.hpp"
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <dlfcn.h>
#endif

std::filesystem::path getExePath()
{
        static std::filesystem::path p = []
        {
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

module_handler_t loadlib(const char *name)
{
        if (auto p = getExePath() / name; std::filesystem::exists(p))
                return loadlib(p.c_str());
        if (auto p = std::filesystem::current_path() / name; std::filesystem::exists(p))
                return loadlib(p.c_str());
        return
#ifdef _WIN32
            LoadLibraryA(name);
#else
            dlopen(name, RTLD_NOW);
#endif
}

void *loadlibproc(module_handler_t h, const char *name)
{
        return
#ifdef _WIN32
            GetProcAddress
#else
            dlsym
#endif
            (h, name);
}

void unloadlib(module_handler_t h)
{
#ifdef _WIN32
        FreeLibrary(h);
#else
        dlclose(h);
#endif
}