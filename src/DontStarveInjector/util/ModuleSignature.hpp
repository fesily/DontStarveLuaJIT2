#pragma once
#include <optional>
#include <string>
#include <vector>
#include "Signature.hpp"

struct cs_insn;
typedef size_t csh;
struct ModuleSignature
{
    void *start_address;
    void *end_address;
    csh hcs;
    cs_insn *insn;
    size_t count;
    int **dp;
    std::vector<std::string> asm_codes;
    ~ModuleSignature();
    static std::optional<ModuleSignature> create(void *start_address, void *end_address);

    void *try_find_pattern(const Signature &target);
};