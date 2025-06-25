#include "game_info.hpp"
#include "MemorySignature.hpp"
#include "ModuleSections.hpp"
#include "disasm.h"
#include <frida-gum.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif
#include <format>
#include <mutex>
#include <string_view>
using namespace std::literals;

static std::string stringToHexAscii(const std::string_view &str) {
    std::string result;
    for (size_t i = 0; i < str.size(); ++i) {
        if (i > 0) result += " ";
        unsigned char c = static_cast<unsigned char>(str[i]);
        result += std::format("{:02X}", c);
    }
    return result;
}
#ifdef _WIN32

#elif defined(__linux__)
static function_relocation::MemorySignature sig_game_info_init_fn = {"48 8D 54 24 10 48 C7 C0 FF FF FF FF"};

static const std::string *shared_name = nullptr;
static const std::string *cluster_name = nullptr;
static const std::string *persist_root = nullptr;
static const std::string *config_dir = nullptr;

bool initGameInfoOffsets() {
    auto mainm = gum_process_get_main_module();
    function_relocation::ModuleSections mainm_sections;
    if (!function_relocation::get_module_sections(gum_module_get_path(mainm), mainm_sections))
        return false;
    if (!sig_game_info_init_fn.scan(mainm_sections.details.path.c_str()))
        return false;
    // find all next mov rex, imm
    int count = 3;
    function_relocation::disasm disasm{(uint8_t *) sig_game_info_init_fn.target_address, 0x256};
    for (auto iter = disasm.begin(), end = disasm.end(); iter != end; ++iter) {
        const auto &insn = *iter;
        auto &x86 = insn.detail->x86;
        if (x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM) {
            auto reg = x86.operands[0].reg;
            auto imm = x86.operands[1].imm;
            if (reg == X86_REG_ESI && mainm_sections.in_rodata(imm)) {
                const char *str = (const char *) imm;
                auto cb = [&iter, &mainm_sections](const std::string *store) {
                    ++iter;
                    auto &next_insn = *iter;
                    auto &next_x86 = next_insn.detail->x86;

                    if (next_x86.op_count == 2 && next_x86.operands[0].type == X86_OP_REG && next_x86.operands[1].type == X86_OP_IMM) {
                        auto &next_reg = next_x86.operands[0].reg;
                        auto &next_imm = next_x86.operands[1].imm;
                        if (next_reg == X86_REG_EDI && mainm_sections.in_bss(next_imm)) {
                            auto ptr_s = reinterpret_cast<const std::string *>(next_imm);
                            store = ptr_s;
                            return true;
                        }
                    }
                    return false;
                };
                if (str == "Master"sv) {
                    if (cb(shared_name)) count--;
                } else if (str == "Cluster_1"sv) {
                    if (cb(cluster_name)) count--;
                } else if (str == ".klei/"sv) {
                    if (cb(persist_root)) count--;
                }

                if (count <= 0) {
                    break;
                }
            }
        }
    }
    if (count > 0) {
        return false;// not enough information found
    }

    // find config_dir
    auto pattern = stringToHexAscii("-config_dir\0"sv);
    function_relocation::MemorySignature sig_config_dir = {pattern.c_str()};
    if (!sig_config_dir.scan(mainm_sections.rodata.base_address, mainm_sections.rodata.size))
        return false;
    uint8_t mov_edi_config_dir[5] = {0xBE, 0x00, 0x00, 0x00, 0x00};// mov edi, imm
    *(uint32_t *) (mov_edi_config_dir + 1) = sig_config_dir.target_address;
    pattern = stringToHexAscii({(const char *) mov_edi_config_dir, 5});
    function_relocation::MemorySignature sig_parser_config_dir = {pattern.c_str()};
    if (!sig_parser_config_dir.scan(mainm_sections.text.base_address, mainm_sections.text.size))
        return false;
    disasm = {(uint8_t *) sig_parser_config_dir.target_address, 0x64};
    for (auto iter = disasm.begin(), end = disasm.end(); iter != end; ++iter) {
        const auto &insn = *iter;
        auto &x86 = insn.detail->x86;
        if (x86.op_count == 2 && x86.operands[0].type == X86_OP_REG && x86.operands[1].type == X86_OP_IMM) {
            auto reg = x86.operands[0].reg;
            auto imm = x86.operands[1].imm;
            if (reg == X86_REG_EDI && mainm_sections.in_bss(imm)) {
                auto ptr_s = reinterpret_cast<const std::string *>(imm);
                config_dir = ptr_s;
                break;
            }
        }
    }
    return config_dir != nullptr && shared_name != nullptr &&
           cluster_name != nullptr && persist_root != nullptr;
}
std::optional<GameInfo> readGameInfo() {
    static std::once_flag init_done;
    static bool initialized = false;
    std::call_once(init_done, []() {
        initialized = initGameInfoOffsets();
    });
    if (!initialized) {
        return std::nullopt;
    }

    GameInfo gameinfo;
    gameinfo.cluster_name = cluster_name ? *cluster_name : "Cluster_1"s;
    gameinfo.shared_name = shared_name ? *shared_name : "Master"s;
    gameinfo.persist_root = persist_root ? *persist_root : ".klei/"s;
    gameinfo.config_dir = config_dir ? *config_dir : "DoNotStarveTogether"s;
    return gameinfo;
}
#elif defined(__APPLE__)
std::optional<GameInfo> readGameInfo() {
    return std::nullopt; // Not implemented for macOS
}
#endif
