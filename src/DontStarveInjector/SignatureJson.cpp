#include <charconv>
#include <fstream>
#include <iostream>
#include <string>
#include <cassert>
#include <charconv>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include "SignatureJson.hpp"
#include "GameVersionFile.hpp"
#include "frida-gum.h"
#include "disasm.h"
#include "MemorySignature.hpp"
#include "ModuleSections.hpp"

using namespace std::literals;

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Signatures, version, funcs);

static std::string get_signatures_filename(bool isClient) {
    return std::filesystem::absolute("signatures_"s + (isClient ? "client" : "server") + ".json").string();
}

const char *SignatureJson::version_path = "../version.txt";

#ifdef __APPLE__

static intptr_t ReadGameVersionFromMemory() {
    using namespace std::literals;
    constexpr auto patten = "48 8D 05 ?? ?? ?? ?? C3"sv;
    function_relocation::MemorySignature signature{patten.data(), 0x0, false};
    function_relocation::ModuleSections section;
    const auto mainModule = gum_process_get_main_module();
    function_relocation::init_module_signature(mainModule->path, 0, section);
    signature.scan(mainModule->range->base_address, mainModule->range->size);
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
