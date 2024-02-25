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

std::string create_signature(void *func, const in_function_t &in_func)
{
    csh hcs;
    cs_arch_register_x86();
    auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &hcs);
    if (ec != CS_ERR_OK)
        return {};
    cs_option(hcs, CS_OPT_DETAIL, CS_OPT_ON);
    std::string ret;

    auto push_asm = [&ret](auto s)
    {
        ret.append(s);
        ret.append(" ");
    };
    const uint8_t *binary = (uint8_t *)func;
    auto insn = cs_malloc(hcs);
    uint64_t address = (uint64_t)func;
    size_t insn_len = 1024;
    auto regx = std::regex(R"(\[rip \+ 0x([0-9a-z]+)\])");
    auto regx1 = std::regex(R"(\[r(.)x \+ rax\*(\d+) \+ 0x([0-9a-z]+)\])");
    auto regx2 = std::regex("0x[0-9a-z]+");
    while (cs_disasm_iter(hcs, &binary, &insn_len, &address, insn))
    {
        ret.append("\n");
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
                        ret.append(is_data((void *)data) ? "(data)" : "(code)");
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
                    auto offset = imm - (insn->address + insn->size);
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
                // 假设远端是一个无关地址的指令
                auto data = (void *)imm;
                ret.append(is_data(data) ? "(data)" : ("(code)" + std::to_string(*(uint32_t *)data)));
            }
            goto IS_END_FUNC;
        }
        case X86_INS_INT3:
            goto IS_END_FUNC;
        case X86_INS_RET:
            goto IS_END_FUNC;
        default:
            continue;
        }
    IS_END_FUNC:
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

static std::unordered_map<void *, std::string> signature_cache;
void release_signature_cache()
{
    signature_cache.clear();
}

void *fix_func_address_by_signature(void *target, void *original, const in_function_t &in_func, uint32_t range, bool updated)
{
    constexpr auto short_signature_len = 16;
    auto original_s = create_signature(original, in_func);
    fprintf(stdout, "---%p---\n%s\n\n\n", original, original_s.c_str());
    {
        auto target_s = create_signature(target, nullptr);
        fprintf(stdout, "---%p---\n%s\n\n\n", target, target_s.c_str());
        if (target_s == original_s)
        {
            return target;
        }
    }
    // 基于以下假设，函数地址必然被对齐分配
    constexpr auto aligned = func_aligned();
    auto limit = range / aligned;

    for (size_t i = 1; i < limit; i++)
    {
        auto fix_target = (void *)((intptr_t)target + i * aligned);
        std::string target_s;
        if (signature_cache.find(fix_target) != signature_cache.end())
        {
            target_s = signature_cache[fix_target];
        }
        else
        {
            target_s = create_signature(fix_target, nullptr);
            signature_cache[fix_target] = target_s;
        }
        if (target_s == original_s)
        {
            return fix_target;
        }
        if (updated)
        {
            fix_target = (void *)((intptr_t)target - i * aligned);
            target_s = create_signature(fix_target, nullptr);
            if (target_s == original_s)
            {
                return fix_target;
            }
        }
    }
    return nullptr;
}