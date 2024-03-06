#pragma once
#include <optional>
#include <string>
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
    ~ModuleSignature();
    int longestCommonSubsequence(std::string text1, std::string text2);
    static std::optional<ModuleSignature> create(void *start_address, void *end_address);
};