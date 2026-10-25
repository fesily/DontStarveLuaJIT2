#pragma once

#include <vector>
#include <unordered_map>
#include <cstdint>
#include <string>
#include <string_view>
#include <algorithm>
#include <frida-gum.h>
#include <memory>
#include <optional>
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
        // Set after ensure_function_features (lazy ScanCtx disasm).
        bool features_ready = false;

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
        GumMemoryRange range{};
        std::string path;
    };
    
    struct ModuleSections {
        ModuleDetials details{};
        // GumMemoryRange is a plain C aggregate; value-initialize so "section not
        // found" is a deterministic 0..0 range instead of stack garbage (the
        // test suite and in_plt()/in_got_plt() rely on that).
        GumMemoryRange text{};
        GumMemoryRange pdata{};
        GumMemoryRange rodata{};
        GumMemoryRange plt{};
        GumMemoryRange got_plt{};
        GumMemoryRange bss{};
#ifndef _WIN32
        GumMemoryRange ehframe{};
#endif  
        std::unordered_map<std::string, GumMemoryRange> sections;
#define MODULESECTION_IN_RANGE(name) \
    bool in_##name(uintptr_t address) const { \
        return name.base_address <= address && address <= name.base_address + name.size; \
    }
        MODULESECTION_IN_RANGE(text)
        MODULESECTION_IN_RANGE(pdata)
        MODULESECTION_IN_RANGE(rodata)
        MODULESECTION_IN_RANGE(bss)
#ifndef _WIN32
        MODULESECTION_IN_RANGE(ehframe)
#endif  

#undef MODULESECTION_IN_RANGE
        bool in_named_section(std::string_view name, uintptr_t address) const {
            const auto it = sections.find(std::string{name});
            return it != sections.end() && address >= it->second.base_address &&
                   address - it->second.base_address < it->second.size;
        }
        bool in_plt(uintptr_t address) const {
            return (address >= plt.base_address && address - plt.base_address < plt.size) ||
                   in_named_section(".plt.sec", address) || in_named_section(".plt.got", address);
        }
        bool in_got_plt(uintptr_t address) const {
            return (address >= got_plt.base_address && address - got_plt.base_address < got_plt.size) ||
                   in_named_section(".got", address);
        }
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
        // The adapter refines ELF bodies with exact FDE extents. This table is
        // the sole authority consumed by the matcher for start|end|size.
        FunctionTable function_table;

        // Symbol names collected during init (before Nucleus rebuild). address -> name.
        // Used only to label Function objects after FunctionTable is applied.
        std::unordered_map<uintptr_t, std::string> symbol_names;

        // Static import table read from the module file: GOT/PLT slot -> imported
        // symbol name. Resolving a PLT target through this map is a property of the
        // FILE, so it cannot be polluted by runtime symbol interposition from other
        // libraries loaded in the same process (which is exactly what breaks the
        // training-library call graph inside the game process).
        std::unordered_map<uintptr_t, std::string> import_slot_names;

        // Defined GLOBAL/WEAK functions from the file: name -> address. Dynamic
        // definitions referenced by PLT relocations take precedence over .symtab.
        // Available after init, before Nucleus function tables exist.
        std::unordered_map<std::string, uintptr_t> own_symbol_addresses;

        uintptr_t own_definition_address(std::string_view name) const {
            const auto it = own_symbol_addresses.find(std::string{name});
            return it == own_symbol_addresses.end() ? 0 : it->second;
        }

        // File-semantics PLT decode: stub -> imported symbol name, following jmp
        // chains, WITHOUT reading the runtime GOT contents. Null when unresolved.
        FUNCTION_RELOCATION_API const std::string *import_name_for_plt_target(uintptr_t target) const;

        // This module's own definition for a symbol name (reference-library
        // semantics). Null when the module does not define it.
        const Function *find_named_function(std::string_view name) const {
            const auto it = known_functions.find(std::string{name});
            return it == known_functions.end() ? nullptr : it->second;
        }

        void set_known_function(uintptr_t addr, const char* name) {
            if (auto func = find_function(addr); func) {
                func->name = name;
                known_functions[name] = func;
            }
        }

        Function *find_function(uintptr_t addr) {
            // address_functions is maintained by apply_nucleus_function_table and
            // covers every materialized span start. The linear fallback below is
            // O(functions) (~4e5 spans) and used to dominate short-body matching.
            if (const auto it = address_functions.find(addr); it != address_functions.end()) {
                return it->second;
            }
            auto iter = std::ranges::find_if(functions, [addr](auto& f) { return addr == f.address; });
            return iter != functions.end() ? &(*iter) : nullptr;
        }

        // --- Lazily built 8-byte window index over a .text sub-range -----------
        // The short-body needle search used to scan the whole target range once
        // per candidate window (thousands of scans per tiny body). Every fixed
        // needle >= 8 bytes contains exactly one 8-byte window, so a single
        // unique-window lookup decides the whole needle.
        struct Window8Index {
            static constexpr uint32_t kMultiple = 0xFFFFFFFFu;
            uintptr_t base = 0;
            size_t size = 0;
            size_t mask = 0;
            std::vector<uint64_t> keys; // value at slot
            std::vector<uint32_t> hits; // first offset, or kMultiple
            std::vector<uint8_t> occupied;
        };

        // Cached per (start, size); built on first use from mapped memory.
        FUNCTION_RELOCATION_API const Window8Index *window8_index(uintptr_t start, size_t size);
        // Unique occurrence address of the 8-byte value in [start, start+size),
        // or nullopt when absent or ambiguous.
        FUNCTION_RELOCATION_API std::optional<uintptr_t>
        find_unique_window8(uintptr_t start, size_t size, uint64_t value);

        std::vector<std::unique_ptr<Window8Index>> window8_cache;

        // 4-byte postings for needles shorter than 8 bytes: sorted (value<<32 |
        // offset) so a lookup is a binary search over a contiguous array.
        struct Window4Index {
            uintptr_t base = 0;
            size_t size = 0;
            std::vector<uint64_t> entries;
        };
        FUNCTION_RELOCATION_API const Window4Index *window4_index(uintptr_t start, size_t size);
        // All occurrences of the 4-byte value inside [start, start+size).
        FUNCTION_RELOCATION_API std::vector<uintptr_t>
        find_window4(uintptr_t start, size_t size, uint32_t value);

        std::vector<std::unique_ptr<Window4Index>> window4_cache;

        FUNCTION_RELOCATION_API uintptr_t try_fix_func_address(const Function &original, SignatureInfo* maybe_addr, uintptr_t limit_address);
    };

    // Load section ranges + symbol name map only. Does NOT invent function
    // boundaries (no CALL/FDE/ret heuristics). Call apply_nucleus_function_table
    // then scan_module_function_features to populate Function bodies.
    FUNCTION_RELOCATION_API bool init_module_signature(const char *path, uintptr_t scan_start_address, ModuleSections &sections);
    FUNCTION_RELOCATION_API bool get_module_sections(const char *path, ModuleSections &sections);

    // Remap Nucleus image-VA table into process VA (sole start|end authority).
    // Rebuilds sections.functions from spans (one Function per span start).
    // Labels known exports via symbol_names. Does NOT split on ScanCtx heuristics.
    // image_base may be 0 (ELF ET_DYN RVA space).
    // Returns false if image_table is empty after remap.
    FUNCTION_RELOCATION_API bool apply_nucleus_function_table(ModuleSections &sections,
                                                             const FunctionTable &image_table,
                                                             uint64_t image_base);

    // Eager features for named exports (train); game modules stay lazy
    // (Function shells only). Requires apply_nucleus_function_table first.
    FUNCTION_RELOCATION_API bool scan_module_function_features(ModuleSections &sections);

    // P2: bytes from entry to first RET / external JMP (cap 256). Cheap.
    FUNCTION_RELOCATION_API size_t function_leaf_size(const Function &fn, size_t cap = 256);

    // P0: on-demand ScanCtx disasm for one body (leaf-clamped). Idempotent.
    FUNCTION_RELOCATION_API bool ensure_function_features(Function &fn);

    // True if [start,start+size) contains a direct CALL/JMP whose PLT/GOT-resolved
    // target equals callee_entry or lies in its FunctionTable span. Unbound PLT
    // targets do not count as callees. No full feature scan.
    FUNCTION_RELOCATION_API bool body_calls_entry(const ModuleSections &mod,
                                                  uint64_t start, size_t size,
                                                  uint64_t callee_entry);
}
