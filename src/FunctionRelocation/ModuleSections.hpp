#pragma once
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <frida-gum.h>
namespace function_relocation
{
struct Const {
    const char* value;
    size_t ref;
};

struct Function {
    uint64_t address;
    size_t size;

    bool in_function(uint64_t addr) const { return address >= addr && address <= addr + size; }

    std::vector<Const*> consts;
    std::vector<uint64_t> call_functions;
    std::vector<int64_t> const_numbers;
    std::vector<int64_t> const_offset_numbers;
    const char* const_key = nullptr;
    size_t consts_hash = 0;

    size_t get_consts_hash();
};

struct ModuleSections {
    GumModuleDetails* details;
    GumMemoryRange text;
    GumMemoryRange rodata;
    GumMemoryRange plt;
    GumMemoryRange got_plt;

    ModuleSections() = default;

    ModuleSections(const ModuleSections&) = delete;

    ModuleSections(ModuleSections&& other) noexcept : details{ other.details } {
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

    std::unordered_map<uint64_t, Function> functions;
    std::unordered_map<const char*, Const> Consts;
    std::unordered_map<Function*, uint64_t> known_functions;

    Function* get_function(uint64_t address);

    uintptr_t try_fix_func_address(Function& original, uint64_t maybe_addr);
};

ModuleSections init_module_signature(const char* path, uintptr_t scan_start_address);
}

