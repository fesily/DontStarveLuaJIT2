#pragma once

#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>
#include <string_view>
#include <algorithm>
#include <frida-gum.h>
#include <memory>
#include <list>


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

        std::vector<std::string> consts;
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


        std::vector<uintptr_t> blocks;
        std::string name;

        std::string_view *const_key = nullptr;
        size_t consts_hash = 0;
        ModuleSections *module = nullptr;

        CodeBlock* get_block(size_t index) const;
    };

    struct ModuleDetials {
        std::string name;
        GumMemoryRange range;
        std::string path;
    };
    
    struct ModuleSections {
        ModuleDetials details;
        GumMemoryRange text;
        GumMemoryRange rodata;
        GumMemoryRange plt;
        GumMemoryRange got_plt;

        bool in_module(uintptr_t address) const;

        bool in_text(uintptr_t address) const;

        bool in_plt(uintptr_t address) const;

        bool in_got_plt(uintptr_t address) const;

        bool in_rodata(uintptr_t address) const;

        std::list<Function> functions;
        std::list<CodeBlock> blocks;
        std::unordered_map<std::string, Const> Consts;
        std::unordered_map<uintptr_t, Function *> address_functions;
        std::unordered_map<uintptr_t, CodeBlock*> address_blocks;
        std::unordered_map<std::string, Function *> known_functions;

        void set_known_function(uintptr_t addr, const char* name) {
            if (auto func = find_function(addr); func) {
                func->name = name;
                known_functions[name] = func;
            }
        }

        Function *find_function(uintptr_t addr) {
            auto iter = std::ranges::find_if(functions, [addr](auto& f) { return addr == f.address; });
            return iter != functions.end() ? &(*iter) : nullptr;
        }

        uintptr_t try_fix_func_address(const Function &original, SignatureInfo* maybe_addr, uintptr_t limit_address);
    };

    bool init_module_signature(const char *path, uintptr_t scan_start_address, ModuleSections &sections);
}

