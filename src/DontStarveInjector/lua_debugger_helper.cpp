#include "lua_debugger_helper.hpp"
#include <string>
#include <filesystem>
#ifdef _WIN32
#include <windows.h>
#else
#endif
#include "util/platform.hpp"
#include <spdlog/spdlog.h>
using namespace std::string_view_literals;
namespace dontstarveinjector::lua_debugger_helper {
    static std::filesystem::path get_home_directory() {
        const char *home_env_vars[] = {
                "USERPROFILE",// Windows
                "HOME",       // Unix-like
                nullptr};
        for (const char **env_var = home_env_vars; *env_var != nullptr; ++env_var) {
            char *home = ::getenv(*env_var);
            if (home)
                return std::filesystem::path(home);
        }
        return {};
    }
    static std::filesystem::path get_vscode_extension_directory(std::filesystem::path const &home_dir) {
        const char *vscodes_dirs[] = {
                ".vscode",
                ".vscode-server",
                ".vscode-remote",
                ".vscode-insiders",
                ".vscode-server-insiders",
                nullptr};
        for (const char **dir = vscodes_dirs; *dir != nullptr; ++dir) {
            std::filesystem::path vscode_ext_dir = home_dir / *dir / "extensions";
            if (std::filesystem::exists(vscode_ext_dir) && std::filesystem::is_directory(vscode_ext_dir)) {
                return vscode_ext_dir;
            }
        }
        return {};
    }
    static std::filesystem::path get_lua_debugger_root_path() {
        auto home_dir = get_home_directory();
        auto vscode_ext_dir = get_vscode_extension_directory(home_dir);
        auto actboy168_lua_debug_key = "actboy168.lua-debug"sv;
        if (!std::filesystem::exists(vscode_ext_dir) && std::filesystem::is_directory(vscode_ext_dir)) return {};
        for (const auto &entry: std::filesystem::directory_iterator(vscode_ext_dir)) {
            if (!entry.is_directory()) continue;
            auto path = entry.path();
            if (path.string().find(actboy168_lua_debug_key) != std::string::npos) {
                return path;
            }
        }
        return {};
    }

    static std::string_view get_lua_vm_type() {
        switch (GetGameLuaContext().luaType)
        {
        case GameLuaType::jit:
            return "luajit";
        case GameLuaType::game:
        case GameLuaType::_51:
        default:
            return "lua51";
        }
    }

    static std::filesystem::path get_lua_debugger_so_path(std::filesystem::path lua_debugger_root) {
        if (lua_debugger_root.empty()) return {};
        const char *os_specific_paths[] = {
            "win32-x64",
            "linux-x64",
            "darwin-x64",
            "linux-arm64",
            "darwin-arm64",
            //"win32-ia32",
            nullptr
        };

        const char *so_exts[] = {
            "dll",
            "so",
            "dylib",
            nullptr
        };
        for (const char **os_path = os_specific_paths; *os_path != nullptr; ++os_path) {
            std::filesystem::path debugger_so_path = lua_debugger_root / "runtime" / *os_path / get_lua_vm_type();
            for (const char **so_ext = so_exts; *so_ext != nullptr; ++so_ext) {
                std::filesystem::path full_path = debugger_so_path / ("luadebug." + std::string(*so_ext));
                if (std::filesystem::exists(full_path) && std::filesystem::is_regular_file(full_path)) {
                    return full_path;
                }
            }
        }
        return {};
    }
#ifdef ENABLE_LUA_DEBUGGER
    void* initialize_lua_debugger() {
        static module_handler_t handler;
        std::string_view env_key = LUA_DEBUG_CORE_DEBUGGER;
        if (getenv(env_key.data()) != nullptr) {
            // already set
            return handler;
        }
        auto lua_debugger_root = get_lua_debugger_root_path();
        if (lua_debugger_root.empty()) return nullptr;
        auto debugger_so_path = get_lua_debugger_so_path(lua_debugger_root).string();
        if (debugger_so_path.empty()) return nullptr;
        handler = loadlib(debugger_so_path.c_str());
        set_env_variable("LUA_DEBUG_CORE", debugger_so_path.c_str());
        set_env_variable(env_key.data(), debugger_so_path.c_str());
        set_env_variable(LUA_DEBUG_CORE_ROOT, lua_debugger_root.string().c_str());
// #ifdef _WIN32
//         if (GetGameLuaContext().luaType == GameLuaType::game) {
//             // get current module dll path 
//             char module_file_name[MAX_PATH] = {0};
//             static HMODULE hModule = NULL;
//             GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
//                       (LPCSTR)initialize_lua_debugger,
//                       &hModule);
//             if (GetModuleFileNameA(hModule, module_file_name, MAX_PATH)) {
//                 set_env_variable("LUA_DEBUG_DLL_PATH", module_file_name);
//             }
//         }
// #endif
        return handler;
    }
#endif
}// namespace dontstarveinjector::lua_debugger_helper