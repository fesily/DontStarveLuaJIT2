#pragma once

#include <string>
#include <functional>
#include <stdint.h>
#include <vector>
#include <unordered_set>

#include <frida-gum.h>

struct _GumMatchPattern;
typedef struct _GumMatchPattern GumMatchPattern;

struct MemorySignature {
    const char *pattern;
    int pattern_offset;
    uintptr_t target_address = 0;
    GumMatchPattern *match_pattern;

    MemorySignature(const char *p, int offset) : pattern{p}, pattern_offset{offset} {}

    uintptr_t scan(const char *m);
};

struct Signature {
    std::vector<std::string> asm_codes;

    std::string to_string() const;

    bool operator==(const Signature &other) const;

    inline size_t size() const { return asm_codes.size(); }

    inline size_t empty() const { return asm_codes.empty(); }

    const std::string &operator[](size_t index) const { return asm_codes[index]; }
};

struct Const {
    const char *value;
    size_t ref;
};

struct Function {
    uint64_t address;
    size_t size;

    bool in_function(uint64_t addr) const { return address >= addr && address <= addr + size; }

    std::vector<Const *> consts;
    std::vector<uint64_t> call_functions;
    std::vector<int64_t> const_numbers;
    const char *const_key = nullptr;
    size_t consts_hash = 0;

    size_t get_consts_hash();
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

    bool in_plt(intptr_t address) const;

    bool in_got_plt(intptr_t address) const;

    bool in_rodata(intptr_t address) const;

    std::unordered_map<uint64_t, Function> functions;
    std::unordered_map<const char *, Const> Consts;
    std::unordered_map<Function *, uint64_t> known_functions;

    Function *get_function(uint64_t address);

    uintptr_t try_fix_func_address(Function &original, uint64_t maybe_addr);
};

bool signature_init();

void signature_deinit();

ModuleSections init_module_signature(const char *path, uintptr_t scan_start_address);

bool is_same_signature_fast(void *target, void *original);

void release_signature_cache();