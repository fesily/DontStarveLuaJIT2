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
#include "export.hpp"
#include "FunctionTable.hpp"


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
        FUNCTION_RELOCATION_API size_t consts_count() const;
        FUNCTION_RELOCATION_API size_t calls_count() const;
        FUNCTION_RELOCATION_API size_t const_count() const;
        FUNCTION_RELOCATION_API size_t const_offset_count() const;


        std::vector<uintptr_t> blocks;
        std::string name;

        std::string_view *const_key = nullptr;
        size_t consts_hash = 0;
        ModuleSections *module = nullptr;

        FUNCTION_RELOCATION_API CodeBlock* get_block(size_t index) const;
    };

    struct ModuleDetials {
        std::string name;
        GumMemoryRange range;
        std::string path;
    };
    
    struct ModuleSections {
        ModuleDetials details;
        GumMemoryRange text;
        GumMemoryRange pdata;
        GumMemoryRange rodata;
        GumMemoryRange plt;
        GumMemoryRange got_plt;
        GumMemoryRange bss;
#ifndef _WIN32
        GumMemoryRange ehframe;
#endif  
        std::unordered_map<std::string, GumMemoryRange> sections;
#define MODULESECTION_IN_RANGE(name) \
    bool in_##name(uintptr_t address) const { \
        return name.base_address <= address && address <= name.base_address + name.size; \
    }
        MODULESECTION_IN_RANGE(text)
        MODULESECTION_IN_RANGE(pdata)
        MODULESECTION_IN_RANGE(rodata)
        MODULESECTION_IN_RANGE(plt)
        MODULESECTION_IN_RANGE(got_plt)
        MODULESECTION_IN_RANGE(bss)
#ifndef _WIN32
        MODULESECTION_IN_RANGE(ehframe)
#endif  

#undef MODULESECTION_IN_RANGE
    bool in_module(uintptr_t address) const {
        return details.range.base_address <= address && address <= details.range.base_address + details.range.size;
    }

        std::list<Function> functions;
        std::list<CodeBlock> blocks;
        std::unordered_map<std::string, Const> Consts;
        std::unordered_map<uintptr_t, Function *> address_functions;
        std::unordered_map<uintptr_t, CodeBlock*> address_blocks;
        std::unordered_map<std::string, Function *> known_functions;

        // Process-VA Nucleus spans (preferred ImageBase remapped to load base).
        // Empty until apply_nucleus_function_table runs for this module.
        FunctionTable function_table;

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

        FUNCTION_RELOCATION_API uintptr_t try_fix_func_address(const Function &original, SignatureInfo* maybe_addr, uintptr_t limit_address);
    };

    FUNCTION_RELOCATION_API bool init_module_signature(const char *path, uintptr_t scan_start_address, ModuleSections &sections);
    FUNCTION_RELOCATION_API bool get_module_sections(const char *path, ModuleSections &sections);

    // Remap Nucleus image-VA table into process VA, store on sections.function_table,
    // and set Function::size from span_containing (authoritative body size).
    // Functions without a containing Nucleus span get size 0 (no residual heuristics).
    // Returns false if image_table is empty or no sizes could be applied.
    // image_base may be 0 (ELF ET_DYN RVA space).
    FUNCTION_RELOCATION_API bool apply_nucleus_function_table(ModuleSections &sections,
                                                             const FunctionTable &image_table,
                                                             uint64_t image_base);
}
