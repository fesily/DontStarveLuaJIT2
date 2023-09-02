#include <Windows.h>
#include <string_view>
#include <functional>
#include <cassert>

#include <frida-gum.h>

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
    char buf[128];
    snprintf(buf, 128, "Signature %s: %p\n", pattern, (void *)target_address);
    OutputDebugStringA(buf);
    return target_address;
}
static bool is_data(void *ptr)
{
    MEMORY_BASIC_INFORMATION info = {};
    VirtualQuery(ptr, &info, sizeof(info));
    return !(info.Protect & PAGE_EXECUTE);
}

std::string create_signature(void *func, void *module_base, const in_function_t &in_func)
{
    csh hcs;
    cs_arch_register_x86();
    auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &hcs);
    if (ec != CS_ERR_OK)
        return {};
    cs_option(hcs, CS_OPT_DETAIL, CS_OPT_ON);
    std::string ret;
    const uint8_t *binary = (uint8_t *)func;
    auto insn = cs_malloc(hcs);
    uint64_t address = (uint64_t)func;
    x86_reg module_base_reg = x86_reg::X86_REG_INVALID;
    size_t insn_len = 1024;
    while (cs_disasm_iter(hcs, &binary, &insn_len, &address, insn))
    {
        static const char const_data[4] = {43, 53, 63, 73};
        static const char jmp_data[4] = {83, 93, 103, 113};
        auto jmp_transform = [](const char *mem) -> const char *
        {
            return jmp_data;
        };
        switch (insn->id)
        {
        case X86_INS_UCOMISD:
        case X86_INS_MOV:
        case X86_INS_LEA:
        {
            std::string_view op_str = insn->op_str;
            if (op_str.find("[rip") != std::string_view::npos)
            {
                auto &operand = insn->detail->x86.operands[1];
                assert(insn->size <= 8 && insn->size >= 6);
                auto insn_op_len = insn->size == 8 ? 4 : (insn->size == 6 ? 2 : 3);
                if (operand.type == x86_op_type::X86_OP_IMM)
                {
                    auto remote_mem = (char *)operand.imm;
                    // maybe data/func
                    ret.append((char *)insn->bytes, insn_op_len);
                    ret.append(is_data(remote_mem) ? const_data : jmp_transform(remote_mem), 4);
                    continue;
                }
                else if (operand.type == x86_op_type::X86_OP_MEM)
                {
                    auto remote_mem = (char *)(operand.mem.disp + insn->address + insn->size);
                    if (module_base == remote_mem)
                    {
                        assert(insn->detail->x86.operands[0].type == x86_op_type::X86_OP_REG);
                        module_base_reg = insn->detail->x86.operands[0].reg;
                    }
                    else
                        module_base_reg = X86_REG_INVALID;

                    // maybe data/func
                    ret.append((char *)insn->bytes, insn_op_len);
                    ret.append(is_data(remote_mem) ? const_data : jmp_transform(remote_mem), 4);
                    continue;
                }
            }
            else
            {
                if (module_base_reg != X86_REG_INVALID)
                {
                    // handler opcode reg, [moude_base_reg + offset_reg + offset]
                    auto &operand = insn->detail->x86.operands[1];
                    if (operand.type == X86_OP_MEM && operand.mem.base == module_base_reg)
                    {
                        assert(insn->size == 7);
                        if (insn->size == 7)
                        {
                            ret.append((char *)insn->bytes, 3);
                            ret.append(const_data, 4);
                        }
                    }
                    module_base_reg = X86_REG_INVALID;
                    continue;
                }
            }
            module_base_reg = X86_REG_INVALID;
            break;
        }

        case X86_INS_JMP:
        {
            auto &operand = insn->detail->x86.operands[0];
            if (operand.type == x86_op_type::X86_OP_IMM)
            {
                auto remote_mem = (char *)operand.imm;
                ret.append((char *)insn->bytes, 1);
                ret.append(jmp_transform(remote_mem), 4);
            }
            else if (operand.type == x86_op_type::X86_OP_MEM)
            {
                auto remote_mem = (char *)(operand.mem.disp + insn->address + insn->size);
                ret.append((char *)insn->bytes, 1);
                ret.append(jmp_transform(remote_mem), 4);
            }
            else
            {
                ret.append((char *)insn->bytes, insn->size);
            }
            goto IS_END_FUNC;
        }
        case X86_INS_INT3:
            goto IS_END_FUNC;
        case X86_INS_RET:
            ret.append((char *)insn->bytes, insn->size);
            goto IS_END_FUNC;
        case X86_INS_CALL:
        {
            auto &operand = insn->detail->x86.operands[0];
            if (operand.type == x86_op_type::X86_OP_IMM)
            {
                auto remote_mem = (char *)operand.imm;
                ret.append((char *)insn->bytes, 1);
                ret.append(jmp_transform(remote_mem), 4);
                continue;
            }
            else if (operand.type == x86_op_type::X86_OP_MEM)
            {
                auto remote_mem = (char *)(operand.mem.disp + insn->address + insn->size);
                ret.append((char *)insn->bytes, 1);
                ret.append(jmp_transform(remote_mem), 4);
                continue;
            }
            break;
        }
        default:
            break;
        }
        ret.append((char *)insn->bytes, insn->size);
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

void *fix_func_address_by_signature(void *target, void *module_base, void *original, void *original_module_base, const in_function_t &in_func)
{
    constexpr auto short_signature_len = 16;
    if (create_signature(target, module_base, nullptr) == create_signature(original, original_module_base, in_func))
    {
        return target;
    }
    // 基于以下假设，函数地址必然被对齐分配
    constexpr auto aligned = func_aligned();
    constexpr auto range = 512;
    constexpr auto limit = range / aligned;
    auto original_s = create_signature(original, original_module_base, in_func);

    for (size_t i = 1; i < limit; i++)
    {
        auto fix_target = (void *)((intptr_t)target + i * aligned);
        auto target_s = create_signature(fix_target, module_base, nullptr);
        if (target_s == original_s)
        {
            return fix_target;
        }
        fix_target = (void *)((intptr_t)target - i * aligned);
        target_s = create_signature(fix_target, module_base, nullptr);
        if (target_s == original_s)
        {
            return fix_target;
        }
    }
    return nullptr;
}