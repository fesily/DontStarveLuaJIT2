#pragma once

#include "disasm.h"
#include "ModuleSections.hpp"

#include <vector>
#include <ranges>
#include <range/v3/all.hpp>
#include <algorithm>
#include <format>

namespace function_relocation {

    static bool reg_is_ip(x86_reg reg) {
        return reg == X86_REG_RIP || reg == X86_REG_EIP || reg == X86_REG_IP;
    };

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

    static uintptr_t filter_jmp_or_call(ModuleSections &m, uintptr_t imm) {
        const auto hcs = get_ctx().hcs;
        auto insn = cs_malloc(hcs);
        auto addr = imm;
        size_t size = 32;
        auto code = (const uint8_t *) imm;
        if (cs_disasm_iter(hcs, &code, &size, reinterpret_cast<uint64_t *>(&addr), insn)) {
            if (insn->id == X86_INS_JMP) {
                auto &op = insn->detail->x86.operands[0];
                if (op.type == X86_OP_MEM) {
                    auto target = insn->address + insn->size + op.mem.disp;
                    if (m.in_got_plt(target)) {
                        imm = (intptr_t) *(void **) target;
                    }
                } else if (op.type == X86_OP_IMM) {
                    imm = op.imm;
                }
            }
        }
        cs_free(insn, 1);
        return imm;
    }

    static uintptr_t read_operand_rip_mem(const cs_insn &insn, const cs_x86_op &op) {
        if (op.type != X86_OP_MEM
            || !reg_is_ip(op.mem.base)
            || op.mem.segment != X86_REG_INVALID
            || op.mem.index != X86_REG_INVALID
            || op.mem.scale != 1)
            return 0;
        return op.mem.disp + insn.address + insn.size;
    }


    static bool address_is_lib_plt(uint8_t *address, uintptr_t target) {
        disasm dis{std::span{address, 8}};
        auto iter = dis.begin();
        const auto &insn = *iter;
        if (insn.id != X86_INS_JMP)
            return false;
        const auto plt = *(uintptr_t *) read_operand_rip_mem(insn, insn.detail->x86.operands[0]);
        return plt == target;
    }

    static void *guess_switch_jump_table_address(disasm &dis, x86_reg switch_jump_table_reg, uintptr_t limit_address) {
        void *target = nullptr;
        for (const auto &insn: dis) {
            if (insn.address >= limit_address) return target;
            if (insn.id != X86_INS_MOV && insn.id != X86_INS_LEA)
                continue;
            const auto &x86_details = insn.detail->x86;
            if (x86_details.disp == 0) continue;

            const auto &operand0 = x86_details.operands[0];
            const auto &operand1 = x86_details.operands[1];
            if (operand0.type == X86_OP_REG && operand0.reg == switch_jump_table_reg) {
                if (operand1.type == X86_OP_MEM && reg_is_ip(operand1.mem.base) &&
                    operand1.mem.index == X86_REG_INVALID &&
                    operand1.mem.segment == X86_REG_INVALID) {
                    target = (void *) (insn.address + insn.size + operand1.mem.disp);
                }
            }
        }
        return target;
    }

    struct ScanCtx {
        ModuleSections &m;

        cs_insn *insns;
        size_t insns_count;
        std::unordered_map<uintptr_t, Function> known_functions;

        ScanCtx(ModuleSections &_m, uint64_t scan_address) : m{_m} {
            scan_address = std::max(m.text.base_address, scan_address);
            const auto address = scan_address;
            const GumMemoryRange &text = {scan_address,
                                          (m.text.base_address + m.text.size - scan_address) / sizeof(char)};
            const auto hcs = get_ctx().hcs;
            cs_option(hcs, CS_OPT_SKIPDATA, CS_OPT_ON);
            insns_count = cs_disasm(hcs, reinterpret_cast<const uint8_t *>(text.base_address), text.size,
                                    address,
                                    0,
                                    &insns);
            cs_option(hcs, CS_OPT_SKIPDATA, CS_OPT_OFF);
        }

        ~ScanCtx() {
            if (insns)
                cs_free(insns, insns_count);
        }

        Function *cur = nullptr;
        CodeBlock *cur_block = nullptr;
        uint64_t function_limit = 0;

        void function_end(uint64_t addr) {
            function_limit = 0;
            cur->size = addr - cur->address;
            cur_block->size = addr - cur_block->address;
            cur = nullptr;
            cur_block = nullptr;
        }

        CodeBlock *createBlock(uint64_t addr) {
            if (auto pre_block = cur_block; pre_block != nullptr)
                pre_block->size = addr - pre_block->address;
            const auto block = &cur->blocks.emplace_back(CodeBlock{addr});
            block->function = cur;
            return block;
        }

        Function *find_known_function(uintptr_t address) {
            if (known_functions.contains(address))
                return &known_functions[address];
            uintptr_t match = 0;
            uintptr_t offset = std::numeric_limits<uintptr_t>::max();
            for (auto &[addr, func]: known_functions) {
                if (addr > address)
                    continue;
                if (address - addr < offset) {
                    offset = address - addr;
                    match = addr;
                }
            }
            return match ? &known_functions[match] : nullptr;
        }
        std::unordered_map<uint64_t, size_t> sureFunctions;
        std::unordered_map<uint64_t, size_t> rodatas;

        auto pre_function() {
            std::unordered_map<uint64_t, std::unordered_set<uint64_t>> maybeFunctions;

            for (const auto &[address, func]: known_functions) {
                sureFunctions[address] = 1;
            }

            for (size_t index = 0; index < insns_count; ++index) {
                const auto &insn = insns[index];
                const auto next_insn_address = insn.address + insn.size;
                const auto &x86_details = insn.detail->x86;
                const auto &operand = x86_details.operands[0];
                const auto &operand1 = x86_details.operands[1];

                if (insn.id == X86_INS_JMP || insn.id == X86_INS_CALL) {
                    if (operand.type != X86_OP_INVALID && operand.type != X86_OP_REG) {
                        if (operand.type == X86_OP_MEM && operand.reg != X86_REG_RIP)
                            continue;
                        uint64_t imm =
                                x86_details.disp == 0 ? operand.imm : next_insn_address + x86_details.disp;
#ifndef _WIN32
                        if (m.in_plt(imm)) {
                            imm = filter_jmp_or_call(m, imm);
                        }
#endif
                        if (m.in_text(imm)) {
                            if (insn.id == X86_INS_JMP) {
                                maybeFunctions[imm].emplace(insn.address);
                                continue;
                            }
                            sureFunctions[imm]++;
#if 0
                            if (m.known_functions.contains(imm)){
                                    fprintf(stderr, "find: %s\n", m.known_functions[imm].c_str());
                                }
#endif

                        }
                    }
                } else if (insn.id == X86_INS_MOV || insn.id == X86_INS_LEA) {
                    if (operand.type == X86_OP_REG && operand1.type == X86_OP_MEM) {
                        auto target = read_operand_rip_mem(insn, operand1);
                        if (target && m.in_rodata(target)) {
                            rodatas[target]++;
                        }
                    }
                }
            }
#ifndef NDEBUG
            for (const auto&[address, func] : known_functions) {
                    const auto guess_size = guess_function_size(address);
                    if (func.size && func.size != guess_size) {
                        fprintf(stderr, "%s", std::format("{} guess func size failed: {} guess {}\n", func.name.c_str(), func.size, guess_size).c_str());
                    }
                }
#endif
            std::unordered_map<uintptr_t, size_t> function_sizes;
            auto maybeFuncs = maybeFunctions
                | ranges::views::filter([this](auto& p){ return !sureFunctions.contains(p.first);})
                | ranges::views::transform([](auto& p) {return std::make_pair(p.first, p.second);})
                | ranges::to<std::vector>();

            std::ranges::sort(maybeFuncs, {}, &decltype(maybeFuncs)::value_type::first);
            for (auto &[addr, ref_addrs]: maybeFuncs) {
                const auto ref_count = ref_addrs.size();
                auto sureFuncs = sureFunctions | std::ranges::views::keys | ranges::to<std::vector>();
                std::ranges::sort(sureFuncs);
                auto near_address = ( sureFuncs | std::ranges::views::filter([addr](auto p) { return p <= addr; }) ).back();
                auto next_address = ( sureFuncs | std::ranges::views::filter([addr](auto p) { return p > addr; }) ).front();
                // all ref address in range
                if (std::ranges::all_of(ref_addrs, [=](auto ref_addr){
                    return ref_addr >= near_address && ref_addr < next_address;
                })) {
                    continue;
                }
                if (!function_sizes.contains(near_address)) {
                    function_sizes[near_address] = guess_function_size(near_address);
                }
                const auto length = function_sizes[near_address];
                if (addr >= near_address + length) {
                    sureFunctions[addr] += ref_count;
                    continue;
                }
                fprintf(stderr, "%p discard the function\n", (void*)addr);
            }

            auto ret = sureFunctions | std::ranges::views::transform([](auto &p) { return p.first; }) |
                       ranges::to<std::vector>();
            ranges::sort(ret);
            return ret;
        }

        void scan() {
            const auto functions = pre_function();
            for (size_t i = 0; i < functions.size(); i++) {
                const auto address = functions[i];
                function_limit = known_functions.contains(address) ?
                    known_functions[address].size + address :
            		(i + 1 == functions.size() ? 0 : functions[i + 1]);

#ifndef NDEBUG
                if (function_limit && known_functions.contains(address)){
                        const auto& func = known_functions[address];
                        if (func.size)
                        assert(func.size + func.address == function_limit);
                    }
#endif
                // function_limit is next function address
                function_limit--;
                if (!scan_function(address)) {
                    fprintf(stderr, "can't find address at insns: %p", (void *) address);
                }
            }
        }

        bool scan_function(uintptr_t address) {
            size_t index = 0;
            for (; index < insns_count; ++index) {
                if (insns[index].address == address)
                    break;
            }
            if (index == insns_count)
                return false;
            assert(cur == nullptr);
            cur = &m.functions.emplace_back(Function{address});
            cur->module = &m;
            cur_block = createBlock(address);
            for (; index < insns_count; ++index) {
                const auto &insn = insns[index];
                cur->insn_count++;
                cur_block->insn_count++;
                const auto next_insn_address = insn.address + insn.size;
                assert(m.in_text(insn.address));
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
#ifndef _WIN32
                            if (m.in_plt(imm)) {
                                imm = filter_jmp_or_call(m, imm);
                            }
#endif
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
                        if (function_limit < next_insn_address) {
                            function_end(next_insn_address);
                            return true;
                        } else {
                            cur_block = createBlock(next_insn_address);
                        }
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
                                cur_block->consts.emplace_back(&m.Consts[str]);
                            }
                        }
                    }
                        break;
                    default:
                        if (insn.id >= X86_INS_JAE && insn.id <= X86_INS_JS) {
                            assert(x86_details.op_count == 1 &&
                                   x86_details.operands[0].type == x86_op_type::X86_OP_IMM);
                            auto addr = static_cast<uint64_t>(x86_details.operands[0].imm);
                            function_limit = std::max(addr, function_limit);

                            cur_block = createBlock(next_insn_address);
                        }
                        break;
                }
            }
            return false;
        }

        size_t guess_function_size(const uintptr_t imm) {
            uintptr_t function_limit = 0;
            x86_reg switch_target_reg = X86_REG_INVALID;
            auto dis = disasm(std::span{(uint8_t *) imm, static_cast<size_t>(-1)});
            for (const auto &insn_ref: dis) {
                auto insn = &insn_ref;
                const auto &x86_details = insn->detail->x86;
                if (insn->id >= X86_INS_JAE && insn->id <= X86_INS_JS) {
                    assert(x86_details.op_count == 1 &&
                           x86_details.operands[0].type == x86_op_type::X86_OP_IMM);
                    auto target_addr = static_cast<uintptr_t>(x86_details.operands[0].imm);
                    function_limit = std::max(target_addr, function_limit);
                } else if (insn->id == X86_INS_JMP || insn->id == X86_INS_RET || insn->id == X86_INS_RETFQ || insn->id == X86_INS_CALL) {
                    if (insn->id == X86_INS_JMP) {
                        if (x86_details.operands[0].type == X86_OP_IMM && insn->size == 2) {
                            // shot jmp
                            const uintptr_t jump_target = x86_details.operands[0].imm;
                            const auto offset = jump_target - (insn->address + insn->size);
                            if (offset <= 255) {
                                function_limit = std::max(jump_target, function_limit);
                            }
                        }
                        if (x86_details.operands[0].type == X86_OP_MEM) {
                            const auto &operand = x86_details.operands[0];
                            if (operand.mem.disp != 0) {
                                // jmp switch table
                                constexpr auto fixed_scale = sizeof(void *) / sizeof(char);
                                using fixed_type = uint64_t;

                                if (operand.mem.scale == fixed_scale && operand.mem.segment == X86_REG_INVALID &&
                                    operand.mem.index == X86_REG_INVALID) {
                                    const auto jump_table = (fixed_type *) operand.mem.disp;
                                    if (m.in_rodata((uintptr_t) jump_table)) {
                                        while (1) {
                                            const auto jump_target = (uintptr_t) *jump_table;
                                            if (!m.in_text(jump_target))
                                                break;
                                            function_limit = std::max(jump_target, function_limit);
                                        }
                                    }
                                }

                            }
                        } else if (x86_details.operands[0].type == X86_OP_REG) {
                            if (x86_details.operands[0].reg == switch_target_reg) {
                                // switch jump
                                function_limit = std::max(static_cast<uintptr_t>(insn->address) + insn->size, function_limit);
                            }
                        }
                    } else if (insn->id == X86_INS_CALL) {
                        if (x86_details.operands[0].type == X86_OP_IMM) {
                            if (function_limit == insn->address) {
#ifndef _WIN32
                                // is __stack_chk_fail?
                                auto target = x86_details.operands[0].imm;
                                static const auto __stack_chk_fail_address = gum_module_find_export_by_name("libc.so.6",
                                    "__stack_chk_fail");
                                if (__stack_chk_fail_address &&
                                    address_is_lib_plt((uint8_t*)target, __stack_chk_fail_address))
                                    return insn->address + insn->size - imm;
#endif
                            }
                        }
                    }
                    if (function_limit < insn->address + insn->size) {
                        return insn->address + insn->size - imm;
                    }
                } else if (insn->id == X86_INS_MOVSXD) {
                    // maybe load switch
                    if (x86_details.operands[0].type == X86_OP_REG) {
                        const auto &operand = x86_details.operands[1];
                        constexpr auto fixed_scale = sizeof(void *) / sizeof(char) / 2;
                        using fixed_type = int32_t;
                        if (operand.type == X86_OP_MEM
                            && operand.mem.scale == fixed_scale) {
                            auto switch_jump_table = operand.mem.base;
                            auto jump_table = static_cast<fixed_type*>(guess_switch_jump_table_address(dis, switch_jump_table,
	                            insn->address));
                            if (jump_table && m.in_rodata((uintptr_t) jump_table)) {
                                switch_target_reg = x86_details.operands[0].reg;
                                auto offset_table = jump_table;
                                assert(rodatas.contains((uintptr_t) jump_table));
                                uintptr_t jump_target = 0;
                                for (int i = 0; i < 9999; i++) {
                                    const auto offset = (*offset_table);
                                    const auto real_address = (uintptr_t) jump_table + offset;
                                    if (!m.in_text(real_address))
                                        break;
                                    jump_target = std::max(real_address, jump_target);
                                    offset_table++;
                                    if (rodatas.contains((uintptr_t) offset_table))
                                        break;
                                }
                                function_limit = std::max(jump_target, function_limit);
                            }
                        }
                    }
                }
            }
            return 0;
        }

    };
}