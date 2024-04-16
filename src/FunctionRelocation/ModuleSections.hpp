#pragma once

#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>
#include <string_view>
#include <algorithm>
#include <frida-gum.h>


namespace function_relocation {
    struct Const {
        std::string_view value;
        size_t ref;
    };
    struct Function;

    struct CodeBlock {
        uint64_t address = 0;
        size_t size = 0;
        size_t insn_count = 0;

        std::vector<Const *> consts;
        std::vector<uint64_t> call_functions;
        std::vector<uint64_t> external_call_functions;
        std::vector<int64_t> const_numbers;
        std::vector<int64_t> const_offset_numbers;
        size_t remote_rip_memory_count = 0;

        Function *function = nullptr;

        bool in_block(uint64_t addr) const { return address >= addr && address <= addr + size; }
    };
    struct ModuleSections;
    struct Function {
        uint64_t address = 0;
        size_t size = 0;
        size_t insn_count = 0;

        bool in_function(uint64_t addr) const { return address >= addr && address <= addr + size; }

        std::string_view* const_key = nullptr;
        size_t consts_hash = 0;
        ModuleSections* module = nullptr;

        std::vector<CodeBlock> blocks;
        std::string name;
    };

    struct ModuleSections {
        GumModuleDetails *details;
        GumMemoryRange text;
        GumMemoryRange rodata;
        GumMemoryRange plt;
        GumMemoryRange got_plt;

        ModuleSections() = default;

        ModuleSections(const ModuleSections &) = delete;

        ModuleSections(ModuleSections &&other) noexcept: details{other.details} {
            other.details = nullptr;
            text = other.text;
            rodata = other.rodata;
            plt = other.plt;
            got_plt = other.got_plt;
        }

        ~ModuleSections();

        bool in_text(uintptr_t address) const;

        bool in_plt(uintptr_t address) const;

        bool in_got_plt(uintptr_t address) const;

        bool in_rodata(uintptr_t address) const;

        std::vector<Function> functions;
        std::unordered_map<const char *, Const> Consts;
        std::unordered_map<uint64_t, std::string> known_functions;

        const Function *find_function(uintptr_t addr) const {
            auto iter = std::ranges::find_if(functions, [addr](auto &f) { return addr == f.address; });
            return iter != functions.end() ? &(*iter) : nullptr;
        }

        uintptr_t try_fix_func_address(const Function &original, uint64_t maybe_addr);
    };

    ModuleSections init_module_signature(const char *path, uintptr_t scan_start_address);
}

