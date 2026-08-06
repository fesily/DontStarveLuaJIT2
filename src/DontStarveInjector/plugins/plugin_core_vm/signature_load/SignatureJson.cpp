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

// Directory of the already-mapped real Injector module (mod_root/bin64 after
// bootstrap). Empty when Injector is not loaded (tools / first boot). Avoid
// PluginPath / DS_INJECTOR_CXX_API here: ds_signature is a STATIC lib also
// linked into signature_updater, which does not import Injector.dll.
static std::filesystem::path injector_dir_if_loaded() {
#ifdef _WIN32
    HMODULE inj = GetModuleHandleW(L"Injector");
    if (!inj) {
        inj = GetModuleHandleA("Injector.dll");
    }
    if (!inj) {
        return {};
    }
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(inj, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return std::filesystem::path(buf).parent_path();
#else
    void *sym = dlsym(RTLD_DEFAULT, "HookStartupEntry");
    if (!sym) {
        return {};
    }
    Dl_info info{};
    if (!dladdr(sym, &info) || !info.dli_fname) {
        return {};
    }
    return std::filesystem::path(info.dli_fname).parent_path();
#endif
}

static std::string get_signatures_filename(bool isClient) {
    const auto file = "signatures_"s + (isClient ? "client" : "server") + ".json";
    // Prefer mod-local bin64 (same directory as real Injector). Fall back to CWD
    // absolute path for legacy game-bin64 installs / first-write creation.
    const auto inj = injector_dir_if_loaded();
    if (!inj.empty()) {
        return (inj / file).string();
    }
    return std::filesystem::absolute(file).string();
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
    spdlog::info("update signatures to file:[{}], version: {}", output, signatures.version);
    std::ofstream sf(output);
    nlohmann::json j;
    nlohmann::to_json(j, signatures);
    sf << j;
}
