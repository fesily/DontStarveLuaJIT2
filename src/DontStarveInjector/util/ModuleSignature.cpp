#include "ModuleSignature.hpp"
#include <frida-gum.h>
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

int ModuleSignature::longestCommonSubsequence(std::string text1, std::string text2)
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
    return res;
}