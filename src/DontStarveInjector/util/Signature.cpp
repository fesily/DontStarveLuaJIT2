#include <string_view>
#include <functional>
#include <cassert>
#include <regex>
#include <array>
#include <frida-gum.h>
#include <optional>

#include "platform.hpp"
#include <charconv>
#include "Signature.hpp"

constexpr auto page = GUM_PAGE_EXECUTE;

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data)
{
    auto self = (MemorySignature *)user_data;
    assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails *details, gpointer user_data)
{
    auto self = (MemorySignature *)user_data;
    gum_memory_scan(details->range, self->match_pattern, sacnBaseAddrCb, user_data);
    return true;
}

uintptr_t MemorySignature::scan(const char *m)
{
    target_address = 0;
    match_pattern = gum_match_pattern_new_from_string(pattern);
    gum_module_enumerate_ranges(m, page, findBaseAddrCb, (gpointer)this);
    gum_match_pattern_unref(match_pattern);
    fprintf(stdout, "Signature %s: %p\n", pattern, (void *)target_address);
    return target_address;
}

std::string Signature::to_string() const
{
    size_t length = 0;
    for (auto &code : this->asm_codes)
    {
        length += code.size();
    }
    std::string ret;
    ret.reserve(length + 1);
    for (auto &code : this->asm_codes)
    {
        ret.append(code);
        ret.append("\n");
    }
    return ret;
}

bool Signature::operator==(const Signature &other) const
{
    if (this->asm_codes.size() != other.asm_codes.size())
        return false;
    for (size_t i = 0; i < this->asm_codes.size(); i++)
    {
        if (this->asm_codes[i] != other.asm_codes[i])
            return false;
    }
    return true;
}

static std::string read_data_string(const char *data)
{
    constexpr auto data_limit = 256;
    if (!gum_memory_is_readable(data - 1, 256 + 1))
        return {};
    if (data[-1] != 0)
        return {};
    for (size_t i = 0; i < data_limit; i++)
    {
        if (!std::isgraph(data[i]))
            return {};
        if (data[i] == 0)
        {
            return std::string(data, data + i);
        }
    }
    return {};
}

static std::string conver_data_ptr(const char *data)
{
    if (!gum_memory_is_readable(data, sizeof(void *)))
    {
        return "(unknown)";
    }
    if (!memory_is_execute((void *)data))
        return "(data)" + read_data_string(data);
    else
    {
        auto str = read_data_string(data);
        if (str.empty())
            return "code";
        return str;
    }
}
static auto regx = std::regex(R"(\[rip \+ 0x([0-9a-z]+)\])");
static auto regx_match = std::regex(R"(.+\[rip \+ 0x([0-9a-z]+)\])");
static auto regx1 = std::regex(R"(\[r(.)x \+ rax\*(\d+) \+ 0x([0-9a-z]+)\])");
static auto regx2 = std::regex("0x[0-9a-z]+");
static std::string filter_signature(cs_insn *insn, bool readRva, uint64_t &maybe_end, bool &is_replaced)
{
    std::string signature;
    std::string op_str = insn->op_str;
    int64_t imm = 0;
    bool rva = false;
    if (op_str.find("[rip") != std::string_view::npos)
    {
        std::smatch result;
        if (std::regex_match(op_str, result, regx_match))
        {
            signature.append(std::regex_replace(op_str, regx, "[rip + 0x??????]"));
            if (readRva && result.size() >= 1)
            {
                const auto &imm_str = result[1].str();
                std::from_chars(imm_str.c_str(), imm_str.c_str() + imm_str.size(), imm, 16);
                if (imm != 0)
                {
                    imm = (uint64_t)insn->address + insn->size + imm;
                    if (insn->id != X86_INS_JMP && insn->id != X86_INS_CALL)
                    {
                        signature.push_back(' ');
                        signature.append(conver_data_ptr((char *)imm));
                    }
                    else
                        rva = true;
                }
            }
        }
    }
    else if (op_str.find("rax*") != std::string_view::npos)
    {
        signature.append((std::regex_replace(op_str, regx1, "[r$1x + rax*$2 + 0x??????]")));
    }
    else
    {
        if (std::regex_match(op_str, regx2))
        {
            // skip 0x
            std::from_chars(op_str.c_str() + 2, op_str.c_str() + op_str.length() + 2, imm, 16);
            if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS)
            {
                signature.append("0x???????");
            }
            else
            {
                if (imm > maybe_end && imm < 512)
                    maybe_end = imm;
                int64_t offset = imm - (insn->address + insn->size);
                signature.append(std::regex_replace(op_str, regx2, std::to_string(offset)));
            }
        }
        else
        {
            signature.append(op_str);
        }
    }
    if (insn->id == X86_INS_JMP || insn->id == X86_INS_CALL)
    {
        if (readRva && imm != 0)
        {
            auto data = (void *)imm;
            if (!gum_memory_is_readable(data, 4))
                return signature;
            if (rva && !memory_is_execute(data))
            {
                data = *(void **)data;
                if (!gum_memory_is_readable(data, 4))
                    return signature;
            }
            is_replaced = true;
            signature.clear();
            auto sub_signatures = create_signature(data, nullptr, 1);
            if (sub_signatures.size() > 0)
                signature = sub_signatures.asm_codes.front();
        }
    }
    return signature;
}

Signature create_signature(void *func, const in_function_t &in_func, size_t limit, bool readRva)
{
    csh hcs;
    cs_arch_register_x86();
    auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &hcs);
    if (ec != CS_ERR_OK)
        return {};
    cs_option(hcs, CS_OPT_DETAIL, CS_OPT_ON);
    Signature ret;

    const uint8_t *binary = (uint8_t *)func;
    auto insn = cs_malloc(hcs);
    uint64_t address = (uint64_t)func;
    size_t insn_len = 1024;
    size_t count = 0;
    uint64_t maybe_end = 0;
    while (cs_disasm_iter(hcs, &binary, &insn_len, &address, insn))
    {
        if (count >= limit)
            break;

        count++;

        ret.asm_codes.push_back({});
        ret.memory_ranges.push_back({insn->address, insn->size});
        std::string &signature = ret.asm_codes.back();
        bool is_replaced = false;
        const auto s2 = filter_signature(insn, readRva, maybe_end, is_replaced);
        if (!is_replaced)
        {
            signature.append(insn->mnemonic);
            signature.push_back(' ');
        }
        signature.append(std::move(s2));
        if (insn->id == X86_INS_JMP || insn->id == X86_INS_INT3 || insn->id == X86_INS_RET)
        {
            if (maybe_end >= (insn->address + insn->size))
                continue;
            if (!in_func || !in_func((void *)((char *)address + insn->size)))
            {
                break;
            }
        }
    }
    cs_free(insn, 1);
    cs_close(&hcs);
    return ret;
}

static constexpr size_t func_aligned()
{
#ifdef _M_X86
    return 8;
#elif defined(__i386__)
    return 8;
#else
    return 16;
#endif
}

static std::unordered_map<void *, Signature> signature_cache;
static std::unordered_map<void *, std::string> signature_first_cache;
void release_signature_cache()
{
    signature_cache.clear();
    signature_first_cache.clear();
}
const Signature *get_signature_cache(void *fix_target, const std::string &first)
{
    Signature *target_s;
    if (signature_cache.find(fix_target) != signature_cache.end())
    {
        target_s = &signature_cache[fix_target];
    }
    else
    {
        auto first_s = create_signature(fix_target, nullptr, 1);
        if (first_s.empty())
            return nullptr;
        if (first_s[0] != first)
        {
            return nullptr;
        }
        signature_cache[fix_target] = create_signature(fix_target, nullptr, size_t(-1), true);
        target_s = &signature_cache[fix_target];
    }
    return target_s;
}

static int longestCommonSubstring(const std::vector<std::string> &text1, const std::vector<std::string> &text2)
{
    int m = text1.size(), n = text2.size();
    std::vector<std::vector<int>> dp(m + 1, std::vector<int>(n + 1));
    for (int i = 1; i <= m; i++)
    {
        auto c1 = text1.at(i - 1);
        for (int j = 1; j <= n; j++)
        {
            auto c2 = text2.at(j - 1);
            if (c1 == c2)
            {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            }
            else
            {
                dp[i][j] = std::max(dp[i - 1][j], dp[i][j - 1]);
            }
        }
    }
    return dp[m][n];
}

#if 1
#define OUTPUT_SIGNATURE(addr, s) fprintf(stderr, "---%p---\n%s\n\n\n", addr, s.c_str())
#else
#define OUTPUT_SIGNATURE(addr, s)
#endif
void *fix_func_address_by_signature(void *target, void *original, const in_function_t &in_func, uint32_t range, bool updated)
{
    constexpr auto short_signature_len = 16;
    if (create_signature(target, nullptr, short_signature_len, false) == create_signature(original, in_func, short_signature_len, false))
    {
        return target;
    }
    auto original_s = create_signature(original, in_func);
    // 基于以下假设，函数地址必然被对齐分配
    constexpr auto aligned = func_aligned();
    auto limit = range / aligned;

    size_t maybe_target_count = 1;
    void *maybe_target_addr = nullptr;

    for (size_t i = 0; i < limit; i++)
    {
        auto fix_target = (void *)((intptr_t)target + i * aligned);
        auto target_s = get_signature_cache(fix_target, original_s[0]);
        if (!target_s)
            continue;
        auto max = longestCommonSubstring(original_s.asm_codes, target_s->asm_codes);
        if (max == original_s.size())
            return fix_target;
        if (max > maybe_target_count)
        {
            maybe_target_count = max;
            maybe_target_addr = fix_target;
        }
        if (updated)
        {
            fix_target = (void *)((intptr_t)target - i * aligned);
            auto target_s = get_signature_cache(fix_target, original_s[0]);
            if (!target_s)
                continue;
            auto max = longestCommonSubstring(original_s.asm_codes, target_s->asm_codes);
            if (max == original_s.size())
                return fix_target;
            if (max > maybe_target_count)
            {
                maybe_target_count = max;
                maybe_target_addr = fix_target;
            }
        }
    }
    if (maybe_target_addr)
    {
        OUTPUT_SIGNATURE(original, original_s.to_string());
        fprintf(stderr, "maybe target:\n");
        OUTPUT_SIGNATURE(maybe_target_addr, get_signature_cache(maybe_target_addr, original_s[0])->to_string());
        return maybe_target_addr;
    }
    OUTPUT_SIGNATURE(original, original_s.to_string());
    return nullptr;
}
