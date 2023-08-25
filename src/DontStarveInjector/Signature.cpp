#include <cassert>
#include <Windows.h>
#include "Signature.hpp"
#include <string_view>

static gboolean sacnBaseAddrCb(GumAddress address, gsize size, gpointer user_data)
{
    auto self = (Signature *)user_data;
    assert(self->target_address == 0);
    self->target_address = address + self->pattern_offset;
    return true;
}

static gboolean findBaseAddrCb(const GumRangeDetails *details, gpointer user_data)
{
    auto self = (Signature *)user_data;
    gum_memory_scan(details->range, self->match_pattern, sacnBaseAddrCb, user_data);
    return true;
}

GumAddress Signature::scan(const char *m)
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

std::string create_signature(void *func, size_t len, void *module_base)
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
    while (cs_disasm_iter(hcs, &binary, &len, &address, insn))
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
                    auto& operand = insn->detail->x86.operands[1];
                    if (operand.type == X86_OP_MEM && operand.mem.base == module_base_reg)
                    {
                        assert(insn->size == 7);
                        if (insn->size == 7) {
                            ret.append((char*)insn->bytes, 3);
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
            goto END_FUNC;
        }
        case X86_INS_INT3:
            goto END_FUNC;
        case X86_INS_RET:
            ret.append((char *)insn->bytes, insn->size);
            goto END_FUNC;
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
    }
END_FUNC:
    cs_free(insn, 1);
    cs_close(&hcs);
    return ret;
}
