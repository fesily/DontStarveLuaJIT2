#pragma once

#include <cctype>
#include <filesystem>
#include <string_view>
#include <string>

// Map a loaded module's directory (parent of the DLL/so/dylib) to the mod
// package root where signatures_{client,server}.json live.
//   <mod>/plugins/plugin_core_vm   -> <mod>     nested pack (actual install)
//   <mod>/plugins                  -> <mod>     flat plugins/*.dll
//   <mod>                          -> <mod>     Injector.dll at package root
//   <mod>/bin64/windows            -> <mod>     legacy shell
inline bool signature_leaf_iequals(const std::filesystem::path &p, std::string_view name) {
    const auto leaf = p.filename().string();
    if (leaf.size() != name.size()) {
        return false;
    }
    for (size_t i = 0; i < leaf.size(); ++i) {
        const auto a = static_cast<unsigned char>(leaf[i]);
        const auto b = static_cast<unsigned char>(name[i]);
        if (std::tolower(a) != std::tolower(b)) {
            return false;
        }
    }
    return true;
}

inline std::filesystem::path signature_strip_shell_dirs(std::filesystem::path p) {
    while (!p.empty()) {
        const auto leaf = p.filename();
        if (leaf == "bin64" || leaf == "bin" || leaf == "windows" || leaf == "linux" ||
            leaf == "osx" || leaf == "lib64" || leaf == "shell") {
            p = p.parent_path();
            continue;
        }
        break;
    }
    return p;
}

inline std::filesystem::path
signature_mod_root_from_module_dir(const std::filesystem::path &module_dir) {
    if (module_dir.empty()) {
        return {};
    }
    const auto parent = module_dir.parent_path();
    // Nested pack: .../plugins/<plugin_id>/
    if (!parent.empty() && signature_leaf_iequals(parent, "plugins")) {
        return parent.parent_path();
    }
    // Flat: .../plugins/
    if (signature_leaf_iequals(module_dir, "plugins")) {
        return module_dir.parent_path();
    }
    return signature_strip_shell_dirs(module_dir);
}
