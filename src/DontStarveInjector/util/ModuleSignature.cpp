#include "ModuleSignature.hpp"
#include <frida-gum.h>
#include <span>

ModuleSignature::~ModuleSignature()
{
    if (insn)
    {
        cs_free(insn, count);
    }
    if (hcs)
    {
        cs_close(&hcs);
    }
    if (dp)
    {
        delete[] dp;
    }
}

static int longestCommonSubsequence(int **&dp, std::span<const std::string> text1, std::span<const std::string> text2)
{
    int text1Length = text1.size(), text2Length = text2.size();
    // Create a 2D array to store lengths of common subsequence at each index.
    if (!dp)
        dp = (int **)new int[(text1Length + 1) * (text2Length + 1)];

    // Initialize the 2D array with zero.
    memset(dp, 0, sizeof(int) * (text1Length + 1) * (text2Length + 1));

    // Loop through both strings and fill the dp array.
    for (int i = 1; i <= text1Length; ++i)
    {
        for (int j = 1; j <= text2Length; ++j)
        {
            // If current characters match, add 1 to the length of the sequence
            // until the previous character from both strings.
            if (text1[i - 1] == text2[j - 1])
            {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            }
            else
            {
                // If current characters do not match, take the maximum length
                // achieved by either skipping the current character of text1 or text2.
                dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }

    // Return the value in the bottom-right cell which contains the
    // length of the longest common subsequence for the entire strings.
    return dp[text1Length][text2Length];
}

extern std::string filter_signature(const cs_insn *insn);

std::optional<ModuleSignature> ModuleSignature::create(void *start_address, void *end_address)
{
    csh hcs = 0;
    auto err = cs_open(CS_ARCH_X86, CS_MODE_64, &hcs);
    if (err != CS_ERR_OK)
    {
        return std::nullopt;
    }
    auto res = ModuleSignature{start_address, end_address, hcs};
    res.count = cs_disasm(res.hcs, (uint8_t *)start_address, (size_t)end_address - (size_t)start_address, (uint64_t)start_address, 0, &res.insn);
    const auto count = res.count;
    for (size_t i = 0; i < count; i++)
    {
        const auto &insn = res.insn[i];
        res.asm_codes.push_back(filter_signature(&insn));
    }
    return res;
}

void *ModuleSignature::try_find_pattern(const Signature &target)
{
    if (target.asm_codes.empty())
        return nullptr;

    int maybe_matched = 0;
    size_t matached_offset = 0;
    auto target_spn = std::span{target.asm_codes.cbegin(), target.size()};
    const auto target_code = target.asm_codes[0];
    for (auto iter = asm_codes.cbegin(), end = asm_codes.cend(); iter != end; iter++)
    {
        const auto &code = *iter;
        if (code != target_code)
            continue;
        auto const offset = iter - end;

        int matched = longestCommonSubsequence(dp, target_spn, {iter, std::min(target.size() + 16, (size_t)(end - iter))});
        if (matched / (float)target.size() > maybe_matched)
        {
            maybe_matched = matched;
            matached_offset = offset;
        }
    }
    if (maybe_matched / (float)target.asm_codes.size() < 0.5)
        return nullptr;
    return (void *)insn[matached_offset].address;
}
