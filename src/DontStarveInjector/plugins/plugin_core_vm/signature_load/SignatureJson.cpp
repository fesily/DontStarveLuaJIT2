#include <charconv>
#include <fstream>
#include <iostream>
#include <string>
#include <cassert>
#include <algorithm>
#include <filesystem>
#include <ranges>
#include <string_view>

#include <spdlog/spdlog.h>
#include <fmt/format.h>
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

// Document layout (SignatureJson::format_version):
// {
//   "format_version": 2,
//   "platforms": {
//     "windows-x64": {"version": 759671, "funcs": {"lua_gettop": {"offset": .., "pattern": "..", "pattern_offset": 0}}},
//     "linux-x64":   {"version": 759671, "funcs": {...}},
//     "macos-arm64": {...}
//   }
// }
// Sections are keyed by "<system>-<arch>", so different systems — and different
// architectures of one system — coexist in a single file. A run only reads and
// rewrites its own section, and a document with the wrong format_version is not
// read at all (the caller rebuilds the DB from the live module).
namespace {

constexpr std::string_view known_systems[] = {"windows"sv, "linux"sv, "macos"sv};
constexpr std::string_view known_archs[] = {"x64"sv, "arm64"sv, "x86"sv};

// "<system>-<arch>"; anything else is not a section this build can own.
bool is_known_platform(std::string_view name) {
    const auto dash = name.find('-');
    if (dash == std::string_view::npos)
        return false;
    const auto system = name.substr(0, dash);
    const auto arch = name.substr(dash + 1);
    return std::ranges::find(known_systems, system) != std::end(known_systems) &&
           std::ranges::find(known_archs, arch) != std::end(known_archs);
}

constexpr const char *host_system() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#else
    return "linux";
#endif
}

constexpr const char *host_arch() {
#if defined(_M_ARM64) || defined(__aarch64__) || defined(__arm64__)
    return "arm64";
#elif defined(_M_IX86) || defined(__i386__)
    return "x86";
#else
    return "x64";
#endif
}

int document_format_version(const nlohmann::json &doc) {
    const auto it = doc.is_object() ? doc.find("format_version") : doc.end();
    if (it == doc.end() || !it->is_number_integer())
        return -1;
    return it->get<int>();
}

// Structural validation of one platform section. A section that cannot be
// trusted is rejected as a whole: keeping half of it would leave zero-offset
// entries that every later scan has to repair.
std::optional<Signatures> parse_platform_section(const nlohmann::json &section, std::string &why) {
    if (!section.is_object()) {
        why = "section is not an object";
        return std::nullopt;
    }
    const auto version = section.find("version");
    if (version == section.end() || !version->is_number_integer()) {
        why = "section has no integer version";
        return std::nullopt;
    }
    const auto funcs = section.find("funcs");
    if (funcs == section.end() || !funcs->is_object() || funcs->empty()) {
        why = "section has no funcs object";
        return std::nullopt;
    }
    Signatures signatures{};
    signatures.version = version->get<uintptr_t>();
    for (const auto &[name, entry]: funcs->items()) {
        const auto offset = entry.is_object() ? entry.find("offset") : entry.end();
        const auto pattern = entry.is_object() ? entry.find("pattern") : entry.end();
        if (offset == entry.end() || !offset->is_number_integer() ||
            pattern == entry.end() || !pattern->is_string()) {
            why = fmt::format("entry '{}' has no integer offset / string pattern", name);
            return std::nullopt;
        }
        function_relocation::SignatureInfo info{
                offset->get<uintptr_t>(), pattern->get<std::string>(), 0};
        const auto pattern_offset = entry.find("pattern_offset");
        if (pattern_offset != entry.end() && pattern_offset->is_number_integer())
            info.pattern_offset = pattern_offset->get<int>();
        if (info.offset == 0 || info.pattern.empty()) {
            why = fmt::format("entry '{}' has a zero offset or empty pattern", name);
            return std::nullopt;
        }
        signatures.funcs.emplace(name, std::move(info));
    }
    return signatures;
}

nlohmann::json platform_section_json(const Signatures &signatures) {
    nlohmann::json funcs = nlohmann::json::object();
    for (const auto &[name, info]: signatures.funcs) {
        funcs[name] = {{"offset", info.offset},
                       {"pattern", info.pattern},
                       {"pattern_offset", info.pattern_offset}};
    }
    return nlohmann::json{{"version", signatures.version}, {"funcs", std::move(funcs)}};
}

}// namespace

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

const char *SignatureJson::platform_name() {
    // One section is one "<system>-<arch>" pair, e.g. "windows-x64" or
    // "macos-arm64": the same file can carry every system and architecture.
    static const std::string name = std::string{host_system()} + "-" + host_arch();
    return name.c_str();
}

std::string SignatureJson::resolved_path() const {
    return file_path.empty() ? get_signatures_filename(isClient) : file_path;
}

std::optional<Signatures> SignatureJson::read_from_signatures() {
    last_read_status = ReadStatus::Missing;
    const auto output = resolved_path();
    if (output.empty()) {
        spdlog::error("read_from_signatures: no signature path (mod root unresolved and file_path empty)");
        return std::nullopt;
    }
    spdlog::info("read signatures from file:[{}]", output);
    std::ifstream sf(output);
    if (!sf.is_open())
        return std::nullopt;
    nlohmann::json doc;
    try {
        sf >> doc;
    } catch (const std::exception &error) {
        last_read_status = ReadStatus::Unusable;
        spdlog::warn("signature DB {} is not valid JSON ({}); regenerating from scratch", output, error.what());
        return std::nullopt;
    }
    const auto stored_format = document_format_version(doc);
    if (stored_format != format_version) {
        last_read_status = ReadStatus::Unusable;
        const std::string found =
                stored_format < 0 ? "missing or not an integer" : std::to_string(stored_format);
        spdlog::warn("signature DB {} has format_version {} but this build writes {}; regenerating from scratch",
                     output, found, format_version);
        return std::nullopt;
    }
    const auto platforms = doc.find("platforms");
    if (platforms == doc.end() || !platforms->is_object()) {
        last_read_status = ReadStatus::Unusable;
        spdlog::warn("signature DB {} has no platforms object; regenerating from scratch", output);
        return std::nullopt;
    }
    for (const auto &[name, section]: platforms->items()) {
        (void) section;
        if (!is_known_platform(name))
            spdlog::warn("signature DB {} carries unknown platform section '{}' (ignored, kept on write)", output,
                         name);
    }
    const auto section = platforms->find(platform_name());
    if (section == platforms->end()) {
        last_read_status = ReadStatus::Unusable;
        spdlog::warn("signature DB {} has no '{}' section; regenerating this platform from scratch", output,
                     platform_name());
        return std::nullopt;
    }
    std::string why;
    auto signatures = parse_platform_section(*section, why);
    if (!signatures) {
        last_read_status = ReadStatus::Unusable;
        spdlog::warn("signature DB {} '{}' section is invalid ({}); regenerating from scratch", output,
                     platform_name(), why);
        return std::nullopt;
    }
    last_read_status = ReadStatus::Ok;
    return signatures;
}

void SignatureJson::update_signatures(const Signatures &signatures) {
    assert(current_version() == signatures.version);
    const auto output = resolved_path();
    if (output.empty()) {
        spdlog::error("update_signatures: no signature path (mod root unresolved and file_path empty)");
        return;
    }
    // Merge into the document already on disk so the sections for the other
    // platforms survive. An unreadable or older document contributes nothing
    // but whatever platform sections it still holds.
    nlohmann::json doc = nlohmann::json::object();
    {
        std::ifstream in(output);
        if (in.is_open()) {
            try {
                in >> doc;
            } catch (const std::exception &error) {
                spdlog::warn("update_signatures: {} is not valid JSON ({})", output, error.what());
                doc = nlohmann::json::object();
            }
        }
    }
    if (!doc.is_object())
        doc = nlohmann::json::object();
    if (const auto platforms = doc.find("platforms"); platforms == doc.end() || !platforms->is_object())
        doc["platforms"] = nlohmann::json::object();
    doc["format_version"] = format_version;
    doc["platforms"][platform_name()] = platform_section_json(signatures);
    spdlog::info("update signatures to file:[{}], platform: {}, version: {}", output, platform_name(),
                 signatures.version);
    std::ofstream sf(output);
    sf << doc;
    sf.flush();
    // An unwritable mod dir used to be silent: generation "succeeded", the DB never
    // landed and every launch regenerated from scratch.
    if (!sf) {
        spdlog::error("update_signatures: failed to write {}", output);
    }
}
