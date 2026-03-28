#include <Windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <unordered_map>

#include "module.hpp"
#include "platform.hpp"

#ifndef GAMEDIR
#error "not defined GAME_DIR"
#endif

#ifndef EXECUTABLE_SUFFIX
#error "not defined EXECUTABLE_SUFFIX"
#endif

#ifndef OUTPUT_HPP_PATH
#error "not defined OUTPUT_HPP_PATH"
#endif

namespace {

constexpr const char *kClientExe = GAMEDIR R"(/bin64/dontstarve_steam_x64)" EXECUTABLE_SUFFIX;
constexpr const char *kOutputHppPath = OUTPUT_HPP_PATH;

bool EqualsIgnoreCase(const std::string_view left, const std::string_view right) {
    if (left.size() != right.size()) {
        return false;
    }
    return std::equal(left.begin(), left.end(), right.begin(), right.end(), [](char a, char b) {
        return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
    });
}

std::string ToLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

struct ImportCollector {
    std::set<std::string> egl_names;
    std::set<std::string> gles_names;
    std::set<uint16_t> egl_ordinals;
    std::set<uint16_t> gles_ordinals;
};

bool CollectAngleImports(const ImportDetails *details, void *user_data) {
    auto *collector = static_cast<ImportCollector *>(user_data);
    if (!details || !collector || !details->module) {
        return true;
    }

    const auto module_name = ToLower(details->module);
    const bool is_egl = EqualsIgnoreCase(module_name, "libegl.dll");
    const bool is_gles = EqualsIgnoreCase(module_name, "libglesv2.dll");
    if (!is_egl && !is_gles) {
        return true;
    }

    if (details->name != nullptr) {
        if (is_egl) {
            collector->egl_names.emplace(details->name);
        } else {
            collector->gles_names.emplace(details->name);
        }
    } else {
        if (is_egl) {
            collector->egl_ordinals.emplace(details->ordinal);
        } else {
            collector->gles_ordinals.emplace(details->ordinal);
        }
    }
    return true;
}

std::unordered_map<uint16_t, std::string> BuildOrdinalNameMap(const char *dll_path) {
    std::unordered_map<uint16_t, std::string> map;
    if (!dll_path) {
        return map;
    }

    auto module = static_cast<HMODULE>(loadlib(dll_path));
    if (!module) {
        return map;
    }

    module_enumerate_exports(module, +[](const ExportDetails *details, void *user_data) -> bool {
        auto *result = static_cast<std::unordered_map<uint16_t, std::string> *>(user_data);
        if (!details || details->name == nullptr || details->ordinal == 0) {
            return true;
        }

        result->try_emplace(details->ordinal, details->name);
        return true;
    }, &map);

    return map;
}

void ResolveOrdinalImports(ImportCollector *collector,
                           const std::unordered_map<uint16_t, std::string> &egl_map,
                           const std::unordered_map<uint16_t, std::string> &gles_map) {
    if (!collector) {
        return;
    }

    std::set<uint16_t> unresolved_egl;
    for (auto ord : collector->egl_ordinals) {
        auto it = egl_map.find(ord);
        if (it != egl_map.end()) {
            collector->egl_names.emplace(it->second);
        } else {
            unresolved_egl.emplace(ord);
        }
    }
    collector->egl_ordinals = std::move(unresolved_egl);

    std::set<uint16_t> unresolved_gles;
    for (auto ord : collector->gles_ordinals) {
        auto it = gles_map.find(ord);
        if (it != gles_map.end()) {
            collector->gles_names.emplace(it->second);
        } else {
            unresolved_gles.emplace(ord);
        }
    }
    collector->gles_ordinals = std::move(unresolved_gles);
}

ImportCollector AnalyzeExecutable(const char *exe_path, const char *tag) {
    std::cout << "========== " << tag << " ==========" << std::endl;
    std::cout << "exe: " << exe_path << std::endl;

    ImportCollector collector;

    auto module = static_cast<HMODULE>(loadlib(exe_path));
    if (!module) {
        std::cerr << "failed to load executable module: " << exe_path << std::endl;
        return collector;
    }

    const auto game_bin_dir = std::filesystem::path(exe_path).parent_path();
    const auto egl_path = game_bin_dir / "libEGL.dll";
    const auto gles_path = game_bin_dir / "libGLESv2.dll";

    std::cout << "loaded libEGL.dll: " << (std::filesystem::exists(egl_path) ? "yes" : "no") << std::endl;
    std::cout << "loaded libGLESv2.dll: " << (std::filesystem::exists(gles_path) ? "yes" : "no") << std::endl;

    module_enumerate_imports(module, &CollectAngleImports, &collector);

    const auto gles_ordinal_map = BuildOrdinalNameMap(gles_path.string().c_str());
    const auto egl_ordinal_map = BuildOrdinalNameMap(egl_path.string().c_str());
    ResolveOrdinalImports(&collector, egl_ordinal_map, gles_ordinal_map);

    std::cout << "EGL names=" << collector.egl_names.size() << ", unresolved ordinals=" << collector.egl_ordinals.size() << std::endl;
    std::cout << "GLES names=" << collector.gles_names.size() << ", unresolved ordinals=" << collector.gles_ordinals.size() << std::endl;

    std::cout << std::endl;
    return collector;
}

void WriteResolverIfs(std::ofstream &out, const std::set<std::string> &names) {
    for (const auto &name : names) {
        out << "    if (strcmp(name, \"" << name << "\") == 0) return reinterpret_cast<FARPROC>(" << name << ");\n";
    }
}

int WriteGeneratedHeader(const ImportCollector &collector) {
    std::ofstream out(kOutputHppPath, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "failed to write generated header: " << kOutputHppPath << std::endl;
        return 1;
    }

    out << "#pragma once\n\n";
    out << "#ifdef _WIN32\n\n";
    out << "#include <EGL/egl.h>\n";
    out << "#include <GLES2/gl2.h>\n";
    out << "#include <Windows.h>\n\n";
    out << "#include <cstring>\n\n";
    out << "namespace angle_iat_generated {\n\n";
    out << "inline FARPROC ResolveViaEglProcAddress(const char *name) {\n";
    out << "    if (!name) {\n";
    out << "        return nullptr;\n";
    out << "    }\n";
    out << "    return reinterpret_cast<FARPROC>(eglGetProcAddress(name));\n";
    out << "}\n\n";

    out << "inline FARPROC ResolveStaticEglSymbol(const char *name) {\n";
    out << "    if (!name) {\n";
    out << "        return nullptr;\n";
    out << "    }\n";
    WriteResolverIfs(out, collector.egl_names);
    out << "    return ResolveViaEglProcAddress(name);\n";
    out << "}\n\n";

    out << "inline FARPROC ResolveStaticGlesSymbol(const char *name) {\n";
    out << "    if (!name) {\n";
    out << "        return nullptr;\n";
    out << "    }\n";
    out << "    auto from_egl = ResolveViaEglProcAddress(name);\n";
    out << "    if (from_egl) {\n";
    out << "        return from_egl;\n";
    out << "    }\n";
    WriteResolverIfs(out, collector.gles_names);
    out << "    return nullptr;\n";
    out << "}\n\n";

    if (!collector.egl_ordinals.empty() || !collector.gles_ordinals.empty()) {
        out << "// Unresolved ordinals captured during generation:\n";
        out << "// These ordinals were imported, but no named export in the DLL resolved to the same address.\n";
        out << "// This usually means the DLL exposes ordinal-only entries with no stable public symbol name.\n";
        out << "// Such imports still fall back to eglGetProcAddress() at runtime when available.\n";
        out << "// To name them statically, inspect the exact ANGLE build symbols or DEF/export metadata.\n";
        out << "//\n";
        for (auto ord : collector.egl_ordinals) {
            out << "// EGL ordinal #" << ord << "\n";
        }
        for (auto ord : collector.gles_ordinals) {
            out << "// GLES ordinal #" << ord << "\n";
        }
        out << "\n";
    }

    out << "} // namespace angle_iat_generated\n\n";
    out << "#endif\n";

    out.close();
    std::cout << "generated header: " << kOutputHppPath << std::endl;
    return 0;
}

} // namespace

int main() {
    const auto client = AnalyzeExecutable(kClientExe, "client");
    std::cout << "Final EGL names: " << client.egl_names.size() << ", unresolved ordinals: " << client.egl_ordinals.size() << std::endl;
    std::cout << "Final GLES names: " << client.gles_names.size() << ", unresolved ordinals: " << client.gles_ordinals.size() << std::endl;

    return WriteGeneratedHeader(client);
}
