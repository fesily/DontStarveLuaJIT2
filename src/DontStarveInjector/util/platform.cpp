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
#include <vector>
#include <string>
#include "platform.hpp"
#include "core/PluginPath.hpp"
#include "util/PathText.hpp"

std::filesystem::path getExePath() {
    static std::filesystem::path p = [] {
#ifdef _WIN32
        // Wide first: the game may live under a path the ANSI code page cannot
        // represent, and path(char*) would decode it through CP_ACP.
        wchar_t path[MAX_PATH * 4] = {};
        const DWORD len =
            GetModuleFileNameW(NULL, path, static_cast<DWORD>(MAX_PATH * 4));
        return std::filesystem::path{std::wstring{path, len}};
#else
        char path[1024];
        ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
        path[len == -1 ? 0 : len] = 0;
        return std::filesystem::path{path};
#endif
    }();
    return p;
}

module_handler_t loadlib(const char *name, int mode) {
    // Callers (e.g. __attribute__((constructor))) can race static init and
    // pass a null/empty name; filesystem::path(const char*) would SEGV on strlen.
    if (!name || !*name) {
        return nullptr;
    }

    namespace fs = std::filesystem;
    const fs::path input{name};

    // Bare basenames (e.g. "lua51") must try the platform shared-library suffix.
    // Otherwise exists(.../"lua51") fails and LoadLibraryA("lua51") only searches
    // the game exe directory — missing mod-local VMs under plugins/deps.
    auto with_platform_suffix = [](const fs::path &p) -> fs::path {
        if (p.has_extension()) {
            return p;
        }
        auto out = p;
#if defined(_WIN32)
        out.concat(L".dll");
#elif defined(__APPLE__)
        out.concat(".dylib");
#else
        out.concat(".so");
#endif
        return out;
    };

    const auto try_load_path = [&](const fs::path &candidate) -> module_handler_t {
        if (candidate.empty()) {
            return nullptr;
        }
        std::error_code ec;
        if (!fs::is_regular_file(candidate, ec)) {
            return nullptr;
        }
#ifdef _WIN32
        // Absolute path + DLL_LOAD_DIR: dependency dir is the VM's own folder (Mod/deps).
        // Do NOT add USER_DIRS here unless AddDllDirectory was called — otherwise
        // LoadLibraryEx can fail with ERROR_INVALID_PARAMETER (0x57) / 0x7E chain.
        // Wide: narrowing a module path through CP_ACP throws error 1113 for names
        // the code page cannot map (and would load the wrong file if it did not).
        return LoadLibraryExW(candidate.c_str(), nullptr,
                              LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
#else
        return dlopen(candidate.native().c_str(), RTLD_NOW | mode);
#endif
    };

    if (auto h = try_load_path(input)) {
        return h;
    }
    if (auto h = try_load_path(with_platform_suffix(input))) {
        return h;
    }

    // Search roots (priority):
    // 1) plugins/deps next to already-mapped plugin_core_vm (canonical for lua51*).
    // 2) plugins/deps derived from Injector: <injector_dir>/../plugins/deps
    // 3) Injector directory (legacy dual-stage)
    // 4) Game exe / cwd (legacy)
    std::vector<fs::path> roots;
    const auto push_root = [&](const fs::path &dir) {
        if (dir.empty()) {
            return;
        }
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) {
            return;
        }
        for (const auto &existing : roots) {
            if (existing == dir) {
                return;
            }
        }
        roots.push_back(dir);
    };

#ifdef _WIN32
    auto module_dir = [](const wchar_t *wname, const char *aname) -> fs::path {
        HMODULE mod = GetModuleHandleW(wname);
        if (!mod && aname) {
            mod = GetModuleHandleA(aname);
        }
        if (!mod) {
            return {};
        }
        wchar_t buf[MAX_PATH];
        const DWORD n = GetModuleFileNameW(mod, buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) {
            return {};
        }
        return fs::path(buf).parent_path();
    };
    const auto core_dir = module_dir(L"plugin_core_vm", "plugin_core_vm.dll");
    if (!core_dir.empty()) {
        // core.vm lives in mod/plugins → mod/deps is the sibling deps tree
        push_root(core_dir.parent_path() / "deps"); // <mod>/deps
        push_root(core_dir / "deps");               // legacy plugins/deps (discarded)
        push_root(core_dir);
    }
    const auto inj_dir = module_dir(L"Injector", "Injector.dll");
    if (!inj_dir.empty()) {
        // <mod>/Injector.dll → <mod>/deps
        push_root(inj_dir / "deps");
        push_root(inj_dir);
    }
#else
    // Locate our OWN module instead of probing the ELF global symbol scope:
    // loadlib() lives in libInjector.so, which sits at the mod root, so this
    // reproduces what the old dlsym(RTLD_DEFAULT, "HookStartupEntry") probe meant —
    // without requiring libInjector/plugin_core_vm to be RTLD_GLOBAL (plugins are
    // loaded RTLD_LOCAL and a same-named plugin export must never be able to
    // redirect this resolution).
    Dl_info self_info{};
    if (dladdr(reinterpret_cast<void *>(&loadlib), &self_info) && self_info.dli_fname != nullptr) {
        const fs::path self_dir = fs::path(self_info.dli_fname).parent_path();
        // <mod>/deps is where lua51* and third-party deps live.
        push_root(self_dir / "deps");
        push_root(self_dir / "plugins" / "deps"); // legacy discarded layout
        push_root(self_dir);
    }
    // Roots registered by whoever actually loaded a module (builtin plugins under
    // <mod>/plugins, and external plugins from arbitrary directories): each one
    // contributes <mod>/deps, <root>/deps and <root>.
    for (const auto &root : ds::plugin::plugin_dll_search_roots()) {
        push_root(root);
    }
#endif

    push_root(getExePath().parent_path());
    {
        std::error_code ec;
        push_root(fs::current_path(ec));
    }
#if defined(__linux__)
    push_root(getExePath().parent_path() / "lib64");
#endif

    const fs::path base = input.filename().empty() ? input : input.filename();
    const fs::path base_suf = with_platform_suffix(base);
#if !defined(_WIN32)
    fs::path base_lib;
    if (!base.has_extension()) {
        const auto &s = base.native();  // POSIX: path bytes, no code page involved
        if (s.rfind("lib", 0) != 0) {
            base_lib = fs::path(std::string("lib") + s +
#if defined(__APPLE__)
                                ".dylib"
#else
                                ".so"
#endif
            );
        }
    }
#endif

    for (const auto &root : roots) {
        if (auto h = try_load_path(root / base_suf)) {
            return h;
        }
        if (auto h = try_load_path(root / base)) {
            return h;
        }
#if !defined(_WIN32)
        if (!base_lib.empty()) {
            if (auto h = try_load_path(root / base_lib)) {
                return h;
            }
        }
#endif
    }

#ifdef _WIN32
    if (auto h = LoadLibraryW(with_platform_suffix(input).c_str())) {
        return h;
    }
    return LoadLibraryA(name);
#else
    if (auto h = dlopen(with_platform_suffix(input).native().c_str(), RTLD_NOW | mode)) {
        return h;
    }
    if (!base_lib.empty()) {
        if (auto h = dlopen(base_lib.native().c_str(), RTLD_NOW | mode)) {
            return h;
        }
    }
    return dlopen(name, RTLD_NOW | mode);
#endif
}

void *loadlibproc(module_handler_t h, const char *name) {
    return
#ifdef _WIN32
        GetProcAddress((HMODULE)h, name);
#else
            dlsym(h == 0 ? RTLD_DEFAULT : h, name);
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

std::string get_cmd(uintptr_t pid) {
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

std::vector<std::string> get_cmds(uintptr_t pid) {
    std::vector<std::string> cmds;
#ifdef _WIN32
    auto cmd = get_cmd(pid);
    int n = 0;
    if (auto argv = CommandLineToArgvW(std::filesystem::path(cmd).wstring().c_str(), &n); argv) {
        cmds.resize(n);
        for (int i = 0; i < n; i++) {
           cmds[i] = ds::util::path_to_utf8(std::filesystem::path(argv[i]));
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

void set_env_variable(const char *key, const char *value) {
#ifdef _WIN32
    _putenv_s(key, value);
#else
    setenv(key, value, 1);
#endif
}

