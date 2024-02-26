#include <string_view>
#include <functional>
#include <cassert>
#include <regex>
#include <array>
#include <frida-gum.h>

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
static bool is_data(void *ptr)
{
    return !memory_is_execute(ptr);
}

std::string Signature::to_string()
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

Signature create_signature(void *func, const in_function_t &in_func, size_t limit)
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
    auto regx = std::regex(R"(\[rip \+ 0x([0-9a-z]+)\])");
    auto regx1 = std::regex(R"(\[r(.)x \+ rax\*(\d+) \+ 0x([0-9a-z]+)\])");
    auto regx2 = std::regex("0x[0-9a-z]+");
    size_t count = 0;
    uint64_t maybe_end = 0;
    while (cs_disasm_iter(hcs, &binary, &insn_len, &address, insn))
    {
        if (count >= limit)
            break;

        count++;

        ret.asm_codes.push_back({});
        std::string &signature = ret.asm_codes.back();
        auto push_asm = [&signature](auto s)
        {
            signature.append(s);
            signature.append(" ");
        };

        push_asm(insn->mnemonic);
        std::string op_str = insn->op_str;
        int64_t imm = 0;
        if (op_str.find("[rip") != std::string_view::npos)
        {
            std::smatch result;
            if (std::regex_match(op_str, result, regx))
            {
                push_asm(std::regex_replace(op_str, regx, "[rip + 0x??????]"));
                if (result.size() == 1)
                {
                    const auto &imm_str = result[1].str();
                    std::from_chars(imm_str.c_str(), imm_str.c_str() + imm_str.size(), imm, 16);
                    if (imm != 0)
                    {
                        auto data = (uint64_t)insn->address + insn->size + imm;
                        signature.append(is_data((void *)data) ? "(data)" : "(code)");
                    }
                }
            }
        }
        else if (op_str.find("rax*") != std::string_view::npos)
        {
            push_asm(std::regex_replace(op_str, regx1, "[r$1x + rax*$2 + 0x??????]"));
        }
        else
        {
            if (std::regex_match(op_str, regx2))
            {
                // skip 0x
                std::from_chars(op_str.c_str() + 2, op_str.c_str() + op_str.length() + 2, imm, 16);
                if (insn->id < X86_INS_JAE || insn->id > X86_INS_JS)
                {
                    push_asm("0x???????");
                }
                else
                {
                    if (imm > maybe_end && imm < 512)
                        maybe_end = imm;
                    int64_t offset = imm - (insn->address + insn->size);
                    push_asm(std::regex_replace(op_str, regx2, std::to_string(offset)));
                }
            }
            else
            {
                push_asm(op_str);
            }
        }
        switch (insn->id)
        {
        case X86_INS_CALL:
        case X86_INS_JMP:
        {
            if (imm != 0)
            {
                auto data = (void *)imm;
                if (is_data(data))
                    signature.append("(data)");
                else
                    signature.append("(code)" + create_signature(data, nullptr, 1).to_string());
            }
            if (insn->id == X86_INS_JMP)
                goto IS_END_FUNC;
            else
                continue;
        }
        case X86_INS_INT3:
            goto IS_END_FUNC;
        case X86_INS_RET:
            goto IS_END_FUNC;
        default:
            continue;
        }
    IS_END_FUNC:
        if (maybe_end >= (insn->address + insn->size))
            continue;
        if (!in_func || !in_func((void *)((char *)address + insn->size)))
        {
            break;
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
void release_signature_cache()
{
    signature_cache.clear();
}

#if 0
#define OUTPUT_SIGNATURE(addr, s) fprintf(stderr, "---%p---\n%s\n\n\n", addr, s.c_str())
#else
#define OUTPUT_SIGNATURE(addr, s)
#endif
void *fix_func_address_by_signature(void *target, void *original, const in_function_t &in_func, uint32_t range, bool updated)
{
    constexpr auto short_signature_len = 16;
    if (create_signature(target, nullptr, short_signature_len) == create_signature(original, in_func, short_signature_len))
    {
        return target;
    }
    auto original_s = create_signature(original, in_func);
    OUTPUT_SIGNATURE(original, original_s.to_string());
    // 基于以下假设，函数地址必然被对齐分配
    constexpr auto aligned = func_aligned();
    auto limit = range / aligned;

    size_t maybe_target_count = 16;
    void *maybe_target_addr = nullptr;
    auto is_target_fn = [&original_s, &maybe_target_count, &maybe_target_addr](Signature target_s, auto fix_target)
    {
        if (target_s == original_s)
        {
            return true;
        }
        if (target_s.size() < original_s.size())
            return false;
        auto count = 0;
        for (size_t i = 0; i < original_s.size(); i++)
        {
            if (target_s[i] == original_s[i])
                count++;
        }
        if (count > maybe_target_count)
        {
            maybe_target_count = count;
            maybe_target_addr = fix_target;
        }
        return false;
    };
    for (size_t i = 0; i < limit; i++)
    {
        auto fix_target = (void *)((intptr_t)target + i * aligned);
        Signature target_s;
        if (signature_cache.find(fix_target) != signature_cache.end())
        {
            target_s = signature_cache[fix_target];
        }
        else
        {
            target_s = create_signature(fix_target, nullptr);
            signature_cache[fix_target] = target_s;
        }
        if (is_target_fn(target_s, fix_target))
        {
            OUTPUT_SIGNATURE(fix_target, target_s.to_string());
            return fix_target;
        }
        if (updated)
        {
            fix_target = (void *)((intptr_t)target - i * aligned);
            target_s = create_signature(fix_target, nullptr);
            if (is_target_fn(target_s, fix_target))
            {
                OUTPUT_SIGNATURE(fix_target, target_s.to_string());
                return fix_target;
            }
        }
    }
    if (maybe_target_addr)
    {
        fprintf(stderr, "maybe target:%p\n", maybe_target_addr);
        return maybe_target_addr;
    }
    return nullptr;
}