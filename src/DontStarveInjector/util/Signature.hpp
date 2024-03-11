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
    struct memory_range {
        uintptr_t start;
        size_t len;
    };
    std::vector<std::string> asm_codes;
    std::vector<memory_range> memory_ranges;

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

    ~ModuleSections();

    bool in_plt(intptr_t address) const;

    bool in_got_plt(intptr_t address) const;

    bool in_rodata(intptr_t address) const;

    std::unordered_map<uint64_t, Function> functions;
    std::unordered_map<const char *, Const> Consts;

    Function *get_function(uint64_t address);
};

bool signature_init();

void signature_deinit();

void init_module_signature(const char *path, uintptr_t scan_address);

using in_function_t = std::function<bool(void *)>;

Signature create_signature(void *func, const in_function_t &in_func, size_t limit = size_t(-1), bool readRva = true);

void *fix_func_address_by_signature(void *target, void *original, const in_function_t &in_func, uint32_t range = 512,
                                    bool updated = true);

void release_signature_cache();