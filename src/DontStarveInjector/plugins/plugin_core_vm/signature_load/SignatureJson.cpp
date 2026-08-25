#include <charconv>
#include <fstream>
#include <iostream>
#include <string>
#include <cassert>
#include <charconv>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include "SignatureJson.hpp"
#include "util/GameVersionFile.hpp"
#include "frida-gum.h"
#include "disasm.h"
#include "MemorySignature.hpp"
#include "ModuleSections.hpp"
#include <filesystem>
#include "SignatureModRoot.hpp"
#ifdef _WIN32
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#else
#  include <dlfcn.h>
#endif

using namespace std::literals;

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Signatures, version, funcs);

// Resolve the mod package root (directory that contains modmain.lua / Injector.dll
// / plugins/). Signatures live at <mod>/signatures_{client,server}.json — NOT
// under bin64/<plat>/ and NOT under deps/. Avoid PluginPath / DS_INJECTOR_CXX_API
// here: ds_signature is a STATIC lib also linked into signature_updater.
static std::filesystem::path module_dir_if_loaded_win(const wchar_t *wname, const char *aname) {
#ifdef _WIN32
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
    return std::filesystem::path(buf).parent_path();
#else
    (void)wname;
    (void)aname;
    return {};
#endif
}

static std::filesystem::path module_dir_if_loaded_sym(const char *sym_name) {
#if !defined(_WIN32)
    void *sym = dlsym(RTLD_DEFAULT, sym_name);
    if (!sym) {
        return {};
    }
    Dl_info info{};
    if (!dladdr(sym, &info) || !info.dli_fname) {
        return {};
    }
    return std::filesystem::path(info.dli_fname).parent_path();
#else
    (void)sym_name;
    return {};
#endif
}

// Canonical: <mod>/  (sibling of plugins/ and deps/).
static std::filesystem::path mod_root_if_loaded() {
#ifdef _WIN32
    const auto core = module_dir_if_loaded_win(L"plugin_core_vm", "plugin_core_vm.dll");
    if (!core.empty()) {
        return signature_mod_root_from_module_dir(core);
    }
    const auto inj = module_dir_if_loaded_win(L"Injector", "Injector.dll");
    if (!inj.empty()) {
        return signature_mod_root_from_module_dir(inj);
    }
#else
    const auto core = module_dir_if_loaded_sym("ds_core_vm_run_signature_and_replace");
    if (!core.empty()) {
        return signature_mod_root_from_module_dir(core);
    }
    const auto inj = module_dir_if_loaded_sym("HookStartupEntry");
    if (!inj.empty()) {
        return signature_mod_root_from_module_dir(inj);
    }
#endif
    return {};
}

static std::string get_signatures_filename(bool isClient) {
    const auto file = "signatures_"s + (isClient ? "client" : "server") + ".json";
    // Only <mod>/signatures_*.json. No CWD/bin64 fallback (stale game-dir copies).
    // Tools must set SignatureJson::file_path or create_or_update(..., path).
    const auto root = mod_root_if_loaded();
    if (root.empty()) {
        spdlog::error("get_signatures_filename: mod root unresolved; set file_path for tools");
        return {};
    }
    return (root / file).string();
}

const char *SignatureJson::version_path = "../version.txt";

#ifdef __APPLE__

static intptr_t ReadGameVersionFromMemory() {
    using namespace std::literals;
    constexpr auto patten = "48 8D 05 ?? ?? ?? ?? C3"sv;
    function_relocation::MemorySignature signature{patten.data(), 0x0, false};
    function_relocation::ModuleSections section;
    const auto mainModule = gum_process_get_main_module();
    function_relocation::init_module_signature(gum_module_get_path(mainModule), 0, section);
    auto range = gum_module_get_range(mainModule);
    signature.scan(range->base_address, range->size);
    uintptr_t version = -1;
    for (const auto address: signature.targets) {
        const auto insn = function_relocation::disasm::get_insn((void *) address, patten.size());
        if (insn->id == X86_INS_LEA) {
            const auto &details = insn->detail->x86;
            const auto target = (char *) X86_REL_ADDR(*insn);
            if (section.in_rodata((uintptr_t) target) && strlen(target) == 6) {
                auto ret = std::from_chars(target, target + 6, version);
                if (ret.ec == std::errc{}) {
                    break;
                }
            }
        }
    }
    return version;
}

#endif

intptr_t SignatureJson::current_version() {
    static auto v =
#ifdef __APPLE__
            ReadGameVersionFromMemory()
#else
    readGameVersion(version_path)
#endif
    ;
    return v;
}

std::optional<Signatures> SignatureJson::read_from_signatures() {
    const auto output = file_path.empty() ? get_signatures_filename(isClient) : file_path;
    if (output.empty()) {
        spdlog::error("read_from_signatures: no signature path (mod root unresolved and file_path empty)");
        return std::nullopt;
    }
    spdlog::info("read signatures from file:[{}]", output);
    std::ifstream sf(output);
    if (!sf.is_open())
        return std::nullopt;
    nlohmann::json j;
    sf >> j;
    return j.get<Signatures>();
}

void SignatureJson::update_signatures(const Signatures &signatures) {
    assert(current_version() == signatures.version);
    const auto output = file_path.empty() ? get_signatures_filename(isClient) : file_path;
    if (output.empty()) {
        spdlog::error("update_signatures: no signature path (mod root unresolved and file_path empty)");
        return;
    }
    spdlog::info("update signatures to file:[{}], version: {}", output, signatures.version);
    std::ofstream sf(output);
    nlohmann::json j;
    nlohmann::to_json(j, signatures);
    sf << j;
}
