#pragma once

#include "disasm.h"
#include "ModuleSections.hpp"

#include <vector>
#include <ranges>
#include <range/v3/all.hpp>
#include <algorithm>
#include <format>
#include <list>

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
#ifndef _WIN32
                    if (m.in_got_plt(target))
#endif

                        imm = (intptr_t) *(void **) target;
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

    static x86_reg reg_32_to_64(x86_reg reg) {
        switch (reg) {
            case X86_REG_EDX:
                return X86_REG_RDX;
            case X86_REG_EAX:
                return X86_REG_RAX;
            case X86_REG_ECX:
                return X86_REG_RCX;
            case X86_REG_EBX:
                return X86_REG_RBX;
            case X86_REG_R8D:
                return X86_REG_R8;
            case X86_REG_R9D:
                return X86_REG_R9;
            case X86_REG_R10D:
                return X86_REG_R10;
            case X86_REG_R11D:
                return X86_REG_R11;
            case X86_REG_R12D:
                return X86_REG_R12;
            case X86_REG_R13D:
                return X86_REG_R13D;
            case X86_REG_R14D:
                return X86_REG_R14D;
            case X86_REG_R15D:
                return X86_REG_R15;
            default:
                return reg;
        }
    }

    static bool guess_the_reg_is_jump_table(disasm &dis, x86_reg reg, uint64_t& jump_table_disp, uint64_t& pre_disp_offset) {
        x86_reg jmp_reg = X86_REG_INVALID;
        x86_reg jmp_pre_reg = X86_REG_INVALID;
        auto check_next_insn_is_add_base = false;
        for (const auto &insn: dis) {
            const auto &x86_details = insn.detail->x86;
            const auto &operand0 = x86_details.operands[0];
            const auto &operand1 = x86_details.operands[1];
            if (insn.id == X86_INS_MOV || insn.id == X86_INS_LEA) {
                if (operand0.type == X86_OP_REG && operand0.reg == reg) {
                    // overwrite the reg is invalid
                    return false;
                }
                if (operand0.type == X86_OP_REG && operand1.type == X86_OP_MEM && operand1.mem.base == reg && operand1.mem.segment == X86_REG_INVALID && operand1.mem.scale == 4) {
                    jmp_reg = reg_32_to_64(operand0.reg);
                    jump_table_disp = operand1.mem.disp;
                    check_next_insn_is_add_base = true;
                    if (jmp_pre_reg != operand1.mem.index) {
                        jmp_pre_reg = X86_REG_INVALID;
                        pre_disp_offset = 0;
                    }
                }
            } else if (insn.id == X86_INS_JMP && operand0.type == X86_OP_REG && operand0.reg == jmp_reg) {
                 break;
            } else if (check_next_insn_is_add_base && insn.id == X86_INS_ADD) {
                if (!(operand0.type == X86_OP_REG && operand1.type == X86_OP_REG && operand0.reg == jmp_reg && operand1.reg == reg))
                    return false;
            } else if (insn.id == X86_INS_MOVZX) {
                if (operand0.type == X86_OP_REG && operand1.type == X86_OP_MEM && operand1.mem.base == reg && operand1.mem.segment == X86_REG_INVALID && operand1.mem.scale == 1) {
                    jmp_pre_reg = reg_32_to_64(operand0.reg);
                    pre_disp_offset = operand1.mem.disp;
                } 
            }
        }
        return jmp_reg != X86_REG_INVALID;
    }

    struct ScanCtx {
        ModuleSections &m;

        std::unordered_map<uintptr_t, Function> known_functions;
        const GumMemoryRange text;

        ScanCtx(ModuleSections &_m, uint64_t scan_address) : m{_m}, text{std::max(m.text.base_address, scan_address),
                                                                         (m.text.base_address + m.text.size - std::max(m.text.base_address, scan_address)) / sizeof(char)}
            {
           
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

        CodeBlock *createBlock(uint64_t addr) const {
            if (auto pre_block = cur_block; pre_block != nullptr)
                pre_block->size = addr - pre_block->address;
            m.blocks.emplace_back(std::make_unique<CodeBlock>(addr));
            auto& block = m.blocks.back();
            block->function = cur;
            cur->blocks.emplace_back(block.get());
            return block.get();
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

        uintptr_t scan_switch_case_rodata(uintptr_t address, x86_reg reg, const std::list<uintptr_t> &case_address, uintptr_t max_address) {
            uint64_t disp = 0;
            uint64_t pre_disp = 0;
            const auto target = m.details->range->base_address;
            auto iter = std::ranges::lower_bound(case_address, address);
            if (iter != case_address.end()) ++iter;

            disasm ds{(uint8_t *) address, iter != case_address.end() ? *iter - address : max_address};
            uintptr_t next_function_address = 0;
            std::list<uintptr_t> my_case_address;
            if (guess_the_reg_is_jump_table(ds, reg, disp, pre_disp)) {
                if (pre_disp) {
                    next_function_address = std::max(next_function_address, guess_pre_jump_table_length(target, pre_disp));
                }
                next_function_address = std::max(next_function_address,
                                                 guess_jump_table_length(target, disp, my_case_address));
            }
            for (auto addr: my_case_address) {
                next_function_address = std::max(next_function_address,
                                                 scan_switch_case_rodata(addr, reg, my_case_address, next_function_address));
            }
            return next_function_address;
        }

        uintptr_t guess_pre_jump_table_length(uintptr_t target, uint64_t pre_disp)
        {
            const auto pre_jump_table_address = pre_disp + target;
            rodatas[pre_jump_table_address]++;

            const uint8_t *pre_jump_table = (uint8_t *) pre_jump_table_address;
            for (int i = 0; i < 65535; ++i) {
                const auto ptr = pre_jump_table + i;
                if ((pre_jump_table_address != (uintptr_t) ptr && rodatas.contains((uintptr_t) ptr)) || *ptr == 0xcc) {
                    return reinterpret_cast<uintptr_t>(ptr);
                }
            }
            return 0;
        }

        uintptr_t guess_jump_table_length(uintptr_t target, uint64_t disp, std::list<uintptr_t> &case_address)
        {

            const auto jump_table_address = disp + target;
            rodatas[jump_table_address]++;

            const auto jump_table = (uint32_t *) jump_table_address;
            for (int i = 0; i < 65535; ++i) {
                const auto ptr = jump_table + i;
                const auto jmp_target = jump_table[i] + m.details->range->base_address;

                if ((jump_table_address != (uintptr_t) ptr && rodatas.contains((uintptr_t) ptr)) || jmp_target > jump_table_address) {
                    return reinterpret_cast<uintptr_t>(ptr);
                }
                case_address.push_back(jmp_target);
            }
            return 0;
        }

        auto pre_function() {
            std::unordered_map<uint64_t, std::unordered_set<uint64_t>> maybeFunctions;

            for (const auto &[address, func]: known_functions) {
                if (address < text.base_address)
                    continue;
                sureFunctions[address] = 1;
            }
            uintptr_t next_function_address = 0;
            disasm ds{(uint8_t *)m.text.base_address, m.text.size};
            auto iter = ds.begin(), end = ds.end();
            for (; iter != end;++iter) {
                const auto &insn = *iter;
                const auto next_insn_address = insn.address + insn.size;
                if (rodatas.contains(next_insn_address)) {
                    assert(next_function_address != 0);
                    iter.reset((uint8_t *) next_function_address);
                    next_function_address = 0;
                    continue;
                }
                const auto &x86_details = insn.detail->x86;
                const auto &operand = x86_details.operands[0];
                const auto &operand1 = x86_details.operands[1];

                if (insn.id == X86_INS_JMP || insn.id == X86_INS_CALL) {
                    if (operand.type != X86_OP_INVALID && operand.type != X86_OP_REG) {
                        if (operand.type == X86_OP_MEM && operand.reg != X86_REG_RIP)
                            continue;
                        uint64_t imm =
                                x86_details.disp == 0 ? operand.imm : next_insn_address + x86_details.disp;
                        if (!m.in_module(imm))
                            continue;
#ifndef _WIN32
                        if (m.in_plt(imm)) 
#else
#endif
                            imm = filter_jmp_or_call(m, imm);
                        if (m.in_text(imm)) {
                            if (text.base_address > imm)
                                continue;
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
                        if (target) {
                            if (m.in_rodata(target)) {
                                rodatas[target]++;
                            }
#ifdef WIN32
                            // the text address maybe jumptable
                            if (target == m.details->range->base_address) {
                                const auto size = m.details->range->base_address + m.details->range->size - next_insn_address;

                                next_function_address = std::max(next_function_address, scan_switch_case_rodata(next_insn_address, operand.reg, {}, next_insn_address + size));
                            }
#endif
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
                auto pre_functions = sureFuncs | std::ranges::views::filter([addr](auto p) { return p <= addr; });
                auto after_functions = sureFuncs | std::ranges::views::filter([addr](auto p) { return p > addr; });
                auto near_address = pre_functions.empty()? m.details->range->base_address : pre_functions.back();
                auto next_address = after_functions.empty()? m.details->range->base_address + m.details->range->size : after_functions.front();
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
            for (int i = 1; i < ret.size(); ++i) {
                const auto cur = ret[i];
                const auto pre = ret[i-1];
                if (ret[i] - ret[i-1] > 0xfff) {
                    
                    continue;
                }
            }
            return ret;
        }

        void scan() {
            const auto functions = pre_function();
            for (size_t i = 0; i < functions.size(); i++) {
                const auto address = functions[i];
                function_limit = known_functions.contains(address) ?
                    known_functions[address].size + address :
            		(i + 1 == functions.size() ? 1 : functions[i + 1]);

#ifndef NDEBUG
                if (function_limit && known_functions.contains(address)){
                        const auto& func = known_functions[address];
                        if (func.size)
                        assert(func.size + func.address == function_limit);
                    }
#endif
				// maybe function_limit has some data
				if (!known_functions.contains(address)) {
                    disasm dis {
                            std::span{(uint8_t *) address, function_limit-address}};
                    auto max_function_limit = address;
                    for (auto iter = dis.begin(),end=dis.end();iter!=end;++iter) {
                        const auto &insn = *iter;
                        // break when data
                        if (rodatas.contains(insn.address)) {
                            max_function_limit = insn.address;
                            break;
                        }
                        max_function_limit = std::max(iter.pre_insn.address, max_function_limit);
                    }
                    function_limit = std::min(max_function_limit, function_limit);
				}
                // function_limit is next function address
                function_limit--;	
                scan_function(address);
            }
        }

        void scan_function(uintptr_t address) {
            size_t index = 0;
            assert(cur == nullptr);
            cur = m.functions.emplace_back(std::make_unique<Function>(address)).get();
            cur->module = &m;
            cur_block = createBlock(address);
            disasm ds{(uint8_t *) address, text.base_address + text.size - address};
            uintptr_t next_insn_address;
            for (const auto & insn: ds) {
                next_insn_address = insn.address + insn.size;
                if (rodatas.contains(next_insn_address)) {
                    function_limit = next_insn_address - 1;
                }
                cur->insn_count++;
                cur_block->insn_count++;
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
                            if (!m.in_module(imm))
                                continue;
#ifndef _WIN32
                            if (m.in_plt(imm))
#endif
                                imm = filter_jmp_or_call(m, imm);

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
            fprintf(stderr, "%s\n", std::format("address[{}] find new function limit:{}", address, next_insn_address).c_str());
            function_end(next_insn_address);
        }

        size_t guess_function_size(const uintptr_t imm) const {
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