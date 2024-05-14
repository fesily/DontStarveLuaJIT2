#pragma once

#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>
#include <string_view>
#include <algorithm>
#include <frida-gum.h>
#include <memory>


struct Signature;

namespace function_relocation {
    struct SignatureInfo;

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

        bool in_block(uint64_t addr) const {
            return address <= addr && addr < address + size;
        }
    };

    struct ModuleSections;

    struct Function {
        uint64_t address = 0;
        size_t size = 0;
        size_t insn_count = 0;

        bool in_function(uint64_t addr) const {
            return address <= addr && addr < address + size;
        }
        size_t consts_count() const;
        size_t calls_count() const;
        size_t const_count() const;
        size_t const_offset_count() const;

        std::string_view *const_key = nullptr;
        size_t consts_hash = 0;
        ModuleSections *module = nullptr;

        std::vector<CodeBlock*> blocks;
        std::string name;
    };

    struct ModuleSections {
        GumModuleDetails *details;
        GumMemoryRange text;
        GumMemoryRange rodata;
        GumMemoryRange plt;
        GumMemoryRange got_plt;

        ModuleSections() = default;

        ModuleSections(const ModuleSections &) noexcept = delete;

        ModuleSections(ModuleSections &&other) noexcept = delete;

        ~ModuleSections();

        bool in_module(uintptr_t address) const;

        bool in_text(uintptr_t address) const;

        bool in_plt(uintptr_t address) const;

        bool in_got_plt(uintptr_t address) const;

        bool in_rodata(uintptr_t address) const;

        std::vector<std::unique_ptr<Function>> functions;
        std::vector<std::unique_ptr<CodeBlock>> blocks;
        std::unordered_map<uintptr_t, Function *> address_functions;
        std::unordered_map<std::string, Function *> known_functions;
        std::unordered_map<const char *, Const> Consts;

        void set_known_function(uintptr_t addr, const char* name) {
            if (auto func = find_function(addr); func) {
                func->name = name;
                known_functions[name] = func;
            }
        }

        Function *find_function(uintptr_t addr) {
            auto iter = std::ranges::find_if(functions, [addr](auto& f) { return addr == f->address; });
            return iter != functions.end() ? (iter->get()) : nullptr;
        }

        uintptr_t try_fix_func_address(const Function &original, SignatureInfo* maybe_addr, uintptr_t limit_address);
    };

    bool init_module_signature(const char *path, uintptr_t scan_start_address, ModuleSections &sections, bool noScan);
}

