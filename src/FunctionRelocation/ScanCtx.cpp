#include "ScanCtx.hpp"
#include "CallTargetResolver.hpp"
#include <spdlog/spdlog.h>


#include <cctype>
#include <cstring>
#include <stdio.h>
#include <fmt/format.h>

namespace function_relocation {

    static const char *read_data_string(const char *data) {
        constexpr auto data_limit = 16;
        if (!gum_memory_is_readable(data, data_limit))
            return nullptr;
        for (size_t i = 0; i < 256; i++) {
            if (!std::isprint(static_cast<unsigned char>(data[i])))
                return data[i] == 0 ? data : nullptr;
        }
        return nullptr;
    }

    ScanCtx::ScanCtx(ModuleSections &_m, uintptr_t scan_address) : m{_m},
                                                                   text{std::max<uintptr_t>(m.text.base_address,
                                                                                            scan_address),
                                                                        (m.text.base_address + m.text.size -
                                                                         std::max<uintptr_t>(m.text.base_address,
                                                                                             scan_address)) /
                                                                                sizeof(char)} {
    }

    void ScanCtx::function_end(uintptr_t addr) {
        function_limit = 0;
        // A feature scan may cover only a prefix. Its end must never shrink
        // the authoritative function span supplied by the discovery table.
        if (body_hard_end == 0) cur->size = addr - cur->address;
        cur_block->size = addr - cur_block->address;
        cur = nullptr;
        cur_block = nullptr;
    }

    CodeBlock *ScanCtx::createBlock(uintptr_t addr) const {
        if (auto pre_block = cur_block; pre_block != nullptr)
            pre_block->size = addr - pre_block->address;
        m.blocks.emplace_back(CodeBlock{addr});
        auto &block = m.blocks.back();
        m.address_blocks[addr] = &block;
        block.function = cur;
        cur->blocks.emplace_back(addr);
        return &block;
    }

    void ScanCtx::scan_function(uintptr_t address) {
        size_t index = 0;
        assert(cur == nullptr);
        // Reuse Function stub from the installed table when present; else create.
        cur = m.find_function(address);
        if (!cur) {
            cur = &m.functions.emplace_back(Function{address});
        } else {
            cur->blocks.clear();
            cur->insn_count = 0;
        }
        cur->module = &m;
        cur_block = createBlock(address);
        // Capstone needs a byte range; body_hard_end bounds it when the caller
        // supplies one.
        const uintptr_t hard_end = body_hard_end != 0
                                           ? body_hard_end
                                           : text.base_address + text.size;
        const size_t available = hard_end > address ? static_cast<size_t>(hard_end - address) : 0;
        disasm ds{(uint8_t *) address, available};
        // Initialised to the entry so a first instruction that cannot be decoded
        // still ends the body somewhere sane.
        uintptr_t next_insn_address = address;
        for (const auto &insn: ds) {
            next_insn_address = insn.address + insn.size;
            if (!m.in_text(insn.address) ||
                (body_hard_end != 0 && insn.address >= body_hard_end)) {
                function_end(insn.address);
                return;
            }
            cur->insn_count++;
            cur_block->insn_count++;
            const auto &x86_details = insn.detail->x86;
            switch (insn.id) {
                case X86_INS_JMP:
                case X86_INS_CALL: {
                    const auto &operand = x86_details.operands[0];
                    if (operand.type != X86_OP_INVALID && operand.type != X86_OP_REG) {
                        if (operand.type == X86_OP_MEM && !reg_is_ip(operand.mem.base))
                            continue;
                        uint64_t imm =
                                x86_details.disp == 0 ? operand.imm : next_insn_address + x86_details.disp;
                        if (!m.in_module(imm))
                            continue;
                        imm = detail::resolve_call_target(m, imm);

                        cur_block->call_functions.emplace_back(imm);
                        if (!m.in_text(imm)) {
                            // unknown function
                            cur_block->external_call_functions.emplace_back(imm);
                        }
                    }
                }
                    [[fallthrough]];
                case X86_INS_RET:
                case X86_INS_RETFQ:
                case X86_INS_NOP:
                    if (function_limit < next_insn_address) {
                        function_end(next_insn_address);
                        return;
                    }
                    cur_block = createBlock(next_insn_address);
                    break;
                    //case X86_INS_MUL:
                    //case X86_INS_IMUL:
                    //case X86_INS_DIV:
                    //case X86_INS_IDIV:
                case X86_INS_ADD:
                case X86_INS_SUB:
                case X86_INS_CMP:
                    if (x86_details.operands[1].type == X86_OP_IMM) {
                        cur_block->const_numbers.push_back(x86_details.operands[1].imm);
                    }
                    break;
                case X86_INS_MOV:
                case X86_INS_LEA: {
                    if (x86_details.op_count == 2) {
                        if (x86_details.disp != 0) {
                            const auto is_offset = ((x86_details.operands[1].type == X86_OP_MEM &&
                                                     !reg_is_ip(x86_details.operands[1].mem.base)) ||
                                                    (x86_details.operands[0].type == X86_OP_MEM &&
                                                     !reg_is_ip(x86_details.operands[0].mem.base)));
                            if (is_offset)
                                cur_block->const_offset_numbers.emplace_back(x86_details.disp);
                            else
                                cur_block->remote_rip_memory_count++;
                        } else if (x86_details.operands[1].type == X86_OP_IMM)
                            cur_block->const_numbers.emplace_back(x86_details.operands[1].imm);
                    }
                    const char *str = nullptr;
                    if (x86_details.op_count == 2 && x86_details.operands[0].type == X86_OP_REG) {
                        const auto &op = x86_details.operands[1];
                        if (insn.id == X86_INS_LEA) {
                            if (op.type == X86_OP_MEM && reg_is_ip(op.mem.base) &&
                                op.mem.index == X86_REG_INVALID &&
                                op.mem.segment == X86_REG_INVALID) {
                                auto target = next_insn_address + op.mem.disp;
                                if (m.in_rodata(target))
                                    str = read_data_string((char *) target);
                            }
                        } else if (insn.id == X86_INS_MOV) {
                            if (op.type == X86_OP_IMM) {
                                auto target = op.imm;
                                if (m.in_rodata(target))
                                    str = read_data_string((char *) target);
                            }
                        }
                        if (str != nullptr && strlen(str) > 0) {
                            if (m.Consts.contains(str)) {
                                m.Consts[str].ref++;
                            } else {
                                m.Consts[str] = {str, 1};
                            }
                            cur_block->consts.emplace_back(str);
                        }
                    }
                } break;
                default:
                    if (insn.id >= X86_INS_JAE && insn.id <= X86_INS_JS) {
                        assert(x86_details.op_count == 1 &&
                               x86_details.operands[0].type == x86_op_type::X86_OP_IMM);
                        auto addr = static_cast<uint64_t>(x86_details.operands[0].imm);
                        function_limit = std::max((uintptr_t) addr, function_limit);
                        if (body_hard_end != 0 && function_limit >= body_hard_end) {
                            function_limit = body_hard_end - 1;
                        }
                        cur_block = createBlock(next_insn_address);
                    }
                    break;
            }
            if (body_hard_end != 0 && next_insn_address >= body_hard_end) {
                function_end(body_hard_end);
                return;
            }
        }
        fprintf(stderr, "%s\n",
                fmt::format("address[{}] find new function limit:{}", address, next_insn_address).c_str());
        function_end(next_insn_address);
    }
}// namespace function_relocation
