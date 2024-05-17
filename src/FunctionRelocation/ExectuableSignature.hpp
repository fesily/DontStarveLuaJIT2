#pragma once
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <unordered_map>
#include <optional>
#include <memory>
#include "ModuleSections.hpp"
namespace function_relocation {
    struct ModuleSections;
    namespace FileSignature {
        constexpr auto file_path = "lua51_signature.msgpack";
        constexpr auto base_address = 0x40000000;
        constexpr auto mem_length = 0x240000;
        struct FileData { 
            ModuleSections section;
            std::unordered_map<uintptr_t, std::vector<uint8_t>> blocks_memory;
            std::shared_ptr<void> buffer;

            void fix_ptr();
        };
        bool create_file_signature(const char *path);
        std::optional<FileData> read_file_signature(const char *file_path);
    }// namespace FileSignature
}// namespace function_relocation