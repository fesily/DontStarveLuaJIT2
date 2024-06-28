#include "ExectuableSignature.hpp"
#include "ModuleSections.hpp"
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <optional>
#include <range/v3/all.hpp>
#include <ranges>
#include <string>
#include <spdlog/spdlog.h>
#include "config.hpp"
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(GumMemoryRange, base_address, size);

namespace function_relocation {
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Const, value, ref);
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(CodeBlock, address, size, insn_count, consts, call_functions, external_call_functions, const_numbers, const_offset_numbers, remote_rip_memory_count);
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(Function, address, size, insn_count, blocks, name);
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ModuleDetials, name, range, path);
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(ModuleSections, details, text, rodata, plt, got_plt, functions, blocks, Consts);

    namespace FileSignature {

        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(FileData, section, blocks_memory);

        bool create_file_signature(const char *path) {
            FileData data;
            if (!init_module_signature(path, 0, data.section)) {
                spdlog::get(logger_name)->error("cannot init module signature:{}", path);
                return false;
            }
            auto &section = data.section;
            auto &blocks_memory = data.blocks_memory;
            assert(section.details.range.base_address == base_address);
            for (auto &fn: section.functions) {
                if (fn.name.starts_with("lua_") || fn.name.starts_with("luaL_")) {
                    for (size_t i = 0; i < fn.blocks.size(); ++i) {
                        auto block = fn.get_block(i);
                        std::vector<uint8_t> buf((uint8_t *) block->address, (uint8_t *) (block->address + block->size));
                        blocks_memory[block->address] = buf;
                    }
                }
            }

            std::filesystem::path output_path{file_path};
            if (getenv("LUA51_SIGNATURE_OUTPUT_DIR") != nullptr)
                output_path = std::filesystem::path(getenv("LUA51_SIGNATURE_OUTPUT_DIR"))/file_path;
            output_path = std::filesystem::absolute(output_path);
            std::ofstream sf{output_path.c_str()};
            spdlog::get(logger_name)->warn("output lua51 signatures file:{}", output_path.string());
            nlohmann::json j;
            nlohmann::to_json(j, data);
            const auto msg = nlohmann::json::to_bjdata(j);
            sf.write((const char *) msg.data(), msg.size());
            return true;
        }
        std::optional<FileData> read_file_signature(const char *file_path) {
            std::ifstream sf{file_path};
            if (!sf.is_open())
                return std::nullopt;
            std::vector<uint8_t> msg;
            const auto length = std::filesystem::file_size(file_path);
            msg.resize(length);
            sf.read((char *) msg.data(), length);
            nlohmann::json j = nlohmann::json::from_bjdata(msg);
            auto data = j.get<FileData>();
            const auto memory = gum_memory_allocate((void *) base_address, mem_length, 16, GUM_PAGE_RW);
            if (memory == 0) {
                fprintf(stderr, "can't alloc memory %p %u\n", (void *) base_address, mem_length);
                return std::nullopt;
            }
            std::memset(memory, 0xcc, mem_length);
            for (const auto &mem: data.blocks_memory) {
                std::memcpy((void *) mem.first, mem.second.data(), mem.second.size());
            }
            data.buffer = {memory, [](auto ptr) {
                               if (ptr) gum_memory_free(ptr, mem_length);
                           }};
            return data;
        }
        void FileData::fix_ptr() {
            // fix the data
            auto range1 = section.functions | std::views::transform([](auto &l) { return std::pair{l.address, &l}; }) | ranges::to<std::vector>();
            section.address_functions = {range1.begin(), range1.end()};
            auto range2 = section.blocks | std::views::transform([](auto &l) { return std::pair{l.address, &l}; }) | ranges::to<std::vector>();
            section.address_blocks = {range2.begin(), range2.end()};
            auto range3 = section.functions | std::views::filter([](auto &fn) { return !fn.name.empty(); }) | std::views::transform([](auto &fn) { return std::pair{fn.name, &fn}; }) | ranges::to<std::vector>();
            section.known_functions = {range3.begin(), range3.end()};
            for (auto &fn: section.functions) {
                fn.module = &section;
                for (size_t i = 0; i < fn.blocks.size(); ++i) {
                    auto block = fn.get_block(i);
                    block->function = &fn;
                }
            }
        }
    }// namespace FileSignature
}// namespace function_relocation