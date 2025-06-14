#include  "ScanCtx.hpp"

#include <unordered_set>
#include <vector>
#include <map>
#include <fmt/format.h>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace function_relocation {

    constexpr auto switch_case_jump_table_inline =
#ifdef __linux__
            false;
#else
            true;
#endif
    enum class SwitchCaseMode {
        Rip,
        ModuleBase,
    };
    constexpr auto switch_case_mode =
#ifdef _WIN32
            SwitchCaseMode::ModuleBase;
#else
            SwitchCaseMode::Rip;
#endif

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

    static bool
    guess_the_reg_is_jump_table(disasm &dis, x86_reg reg, uint64_t &jump_table_disp, uint64_t &pre_disp_offset) {
        x86_reg jmp_reg = X86_REG_INVALID;
        x86_reg jmp_pre_reg = X86_REG_INVALID;
        auto check_next_insn_is_add_base = false;
        for (const auto &insn: dis) {
            const auto &x86_details = insn.detail->x86;
            const auto &operand0 = x86_details.operands[0];
            const auto &operand1 = x86_details.operands[1];
            if (insn.id == X86_INS_MOV || insn.id == X86_INS_LEA || insn.id == X86_INS_MOVSXD) {
                if (operand0.type == X86_OP_REG && operand0.reg == reg) {
                    // overwrite the reg is invalid
                    return false;
                }
                if (operand0.type == X86_OP_REG && operand1.type == X86_OP_MEM && operand1.mem.base == reg &&
                    operand1.mem.segment == X86_REG_INVALID && operand1.mem.scale == 4) {
                    jmp_reg = insn.id == X86_INS_MOVSXD ? operand0.reg : reg_32_to_64(operand0.reg);
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
                if (!(operand0.type == X86_OP_REG && operand1.type == X86_OP_REG && operand0.reg == jmp_reg &&
                      operand1.reg == reg))
                    return false;
            } else if (insn.id == X86_INS_MOVZX) {
                if (operand0.type == X86_OP_REG && operand1.type == X86_OP_MEM && operand1.mem.base == reg &&
                    operand1.mem.segment == X86_REG_INVALID && operand1.mem.scale == 1) {
                    jmp_pre_reg = reg_32_to_64(operand0.reg);
                    pre_disp_offset = operand1.mem.disp;
                }
            }
        }
        return jmp_reg != X86_REG_INVALID;
    }

    struct ScanSwitchCase {
        ScanCtx &ctx;
        std::map<uintptr_t, std::set<uintptr_t>> switch_jump_tables;


        uintptr_t scan_switch_case_rodata(uintptr_t base_address, uintptr_t start_scan_address, x86_reg reg,
                                          const std::list<uintptr_t> &case_address,
                                          uintptr_t max_address) {
            uint64_t disp = 0;
            uint64_t pre_disp = 0;
            auto iter = std::ranges::lower_bound(case_address, start_scan_address);
            if (iter != case_address.end()) ++iter;

            disasm ds{(uint8_t *) start_scan_address,
                      iter != case_address.end() ? *iter - start_scan_address : max_address};
            uintptr_t next_function_address = 0;
            if (guess_the_reg_is_jump_table(ds, reg, disp, pre_disp)) {
                if (pre_disp) {
                    next_function_address = std::max(next_function_address,
                                                     guess_pre_jump_table_length(base_address, pre_disp));
                }
                const auto jump_table_address = base_address + disp;
                next_function_address = std::max(next_function_address,
                                                 guess_jump_table_length(base_address, disp));
            }

            return next_function_address;
        }


        uintptr_t guess_pre_jump_table_length(uintptr_t target, uint64_t pre_disp) {
            const auto pre_jump_table_address = pre_disp + target;
            ctx.rodatas[pre_jump_table_address]++;

            const uint8_t *pre_jump_table = (uint8_t *) pre_jump_table_address;
            for (int i = 0; i < 65535; ++i) {
                const auto ptr = pre_jump_table + i;
                if ((pre_jump_table_address != (uintptr_t) ptr && ctx.rodatas.contains((uintptr_t) ptr)) ||
                    *ptr == 0xcc) {
                    return reinterpret_cast<uintptr_t>(ptr);
                }
            }
            return 0;
        }

        uintptr_t
        guess_jump_table_length(uintptr_t base_address, uint64_t disp) {
            const auto jump_table_address = disp + base_address;
            ctx.rodatas[jump_table_address]++;
            if (switch_jump_tables.contains(jump_table_address))
                return std::ranges::max(switch_jump_tables[jump_table_address]);
            // try fix other table address;
            for (auto &[addr, tab]: switch_jump_tables) {
                if (addr == jump_table_address || !tab.contains(jump_table_address)) continue;
                assert(addr < jump_table_address);
                tab =
                        tab | std::views::filter([jump_table_address](auto p) { return p < jump_table_address; }) |
                        ranges::to<std::set>();
            }
            auto &case_address = switch_jump_tables[jump_table_address];

            const auto jump_table = (int32_t *) jump_table_address;
            for (int i = 0; i < 65535; ++i) {
                const auto ptr = jump_table + i;
                const auto jmp_target = jump_table[i] + base_address;

                if ((jump_table_address != (uintptr_t) ptr && ctx.rodatas.contains((uintptr_t) ptr)) ||
                    jmp_target > jump_table_address) {
                    return reinterpret_cast<uintptr_t>(ptr);
                }
                if (std::abs(jump_table[i]) > 65536)
                    return reinterpret_cast<uintptr_t>(ptr);
                case_address.emplace(jmp_target);
            }
            return jump_table_address;
        }


    };

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
        cur->size = addr - cur->address;
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

    Function *ScanCtx::find_known_function(uintptr_t address) {
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

    static auto scan_pre_text_range(ScanCtx &ctx) {
        std::unordered_map<uint64_t, std::unordered_set<uint64_t>> maybeFunctions;
        auto range = ctx.m.text;
        for (auto ptr = (uint8_t *) range.base_address, end = (uint8_t *) range.base_address + range.size;
                ptr < end;) {
            auto code = *ptr;
            // call
            if (code == 0xE8 || code == 0xE9) {
                const auto p = ptr;
                const auto offset = (int32_t *) (ptr + 1);
                const uintptr_t addr = ((uintptr_t) (ptr + 5)) + *offset;
                if (ctx.m.in_text(addr) && addr >= ctx.text.base_address) {
                    ptr += 5;
                    if (code == 0xE8)
                        ++ctx.sureFunctions[addr];
                    else if (code == 0xE9)
                        maybeFunctions[addr].emplace((uintptr_t) p);
                    continue;
                }
            }
            ++ptr;
        }
#ifdef _WIN32
        auto module_base_address = ctx.m.details.range.base_address;
        range = ctx.m.pdata;
        std::vector<std::pair<RUNTIME_FUNCTION, std::vector<RUNTIME_FUNCTION>>> runtime_functions;
        for (auto ptr = (uint8_t *) range.base_address, end = (uint8_t *) range.base_address + range.size;
        ptr < end; ptr+=12) {
            PRUNTIME_FUNCTION function = (PRUNTIME_FUNCTION) ptr;
            if (function->BeginAddress == 0) break;
            if (!runtime_functions.empty() && runtime_functions.back().first.EndAddress == function->BeginAddress) {
                runtime_functions.back().second.emplace_back(*function);
            } else {
                auto blockBeing = module_base_address + function->BeginAddress;
                auto blockEnding = module_base_address + function->EndAddress;
                assert(ctx.m.in_text(blockBeing) && ctx.m.in_text(blockEnding));
                runtime_functions.emplace_back(*function, std::vector<RUNTIME_FUNCTION>{*function});
                if (!ctx.sureFunctions.contains(blockBeing))
                    ctx.sureFunctions[blockBeing] = 0;
            }
        }
#endif
        return maybeFunctions;
    }

    std::vector<uintptr_t> ScanCtx::pre_function() {
        std::unordered_map<uint64_t, std::unordered_set<uint64_t>> maybeFunctions = scan_pre_text_range(*this);

        for (const auto &[address, func]: known_functions) {
            if (address < text.base_address)
                continue;
            sureFunctions[address] = 1;
        }
        uintptr_t next_function_address = 0;
        disasm ds{(uint8_t *) text.base_address, text.size};
        for (auto iter = ds.begin(), end = ds.end(); iter != end; ++iter) {
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
                        // the text address maybe jumptable
                        if constexpr (switch_case_jump_table_inline) {
                            bool scan_switch_case = (switch_case_mode == SwitchCaseMode::ModuleBase &&
                                                     target == m.details.range.base_address) ||
                                                    (switch_case_mode == SwitchCaseMode::Rip && m.in_text(target));
                            if (scan_switch_case) {
                                const auto size =
                                        m.details.range.base_address + m.details.range.size - next_insn_address;
                                const uintptr_t jump_table_base_address =
                                        switch_case_mode == SwitchCaseMode::ModuleBase ? m.details.range.base_address
                                                                                       : target;
                                ScanSwitchCase scanner{*this};
                                next_function_address = std::max(next_function_address,
                                                                 scanner.scan_switch_case_rodata(
                                                                         jump_table_base_address,
                                                                         next_insn_address,
                                                                         operand.reg,
                                                                         {},
                                                                         next_insn_address +
                                                                         size));
                            }
                        }
                    }
                }
            }
        }
#ifndef NDEBUG
        for (const auto &[address, func]: known_functions) {
            const auto guess_size = guess_function_size(address);
            if (func.size && func.size != guess_size) {
                fprintf(stderr, "%s",
                        fmt::format("{} guess func size failed: {} guess {}\n", func.name.c_str(), func.size,
                                    guess_size).c_str());
            }
        }
#endif
        std::unordered_map<uintptr_t, size_t> function_sizes;
        auto maybeFuncs = maybeFunctions
                          | ranges::views::filter([this](auto &p) { return !sureFunctions.contains(p.first); })
                          | ranges::views::transform([](auto &p) { return std::make_pair(p.first, p.second); })
                          | ranges::to<std::vector>();

        std::ranges::sort(maybeFuncs, {}, &decltype(maybeFuncs)::value_type::first);
        for (auto &[addr, ref_addrs]: maybeFuncs) {
            if (addr < text.base_address) {
                fprintf(stderr, "%p discard less base address the function\n", (void *) addr);
                continue;
            }
            const auto ref_count = ref_addrs.size();
            auto sureFuncs = sureFunctions | std::ranges::views::keys | ranges::to<std::vector>();
            std::ranges::sort(sureFuncs);
            auto pre_functions = sureFuncs | std::ranges::views::filter([addr](auto p) { return p <= addr; });
            auto after_functions = sureFuncs | std::ranges::views::filter([addr](auto p) { return p > addr; });
            auto near_address = pre_functions.empty() ? m.details.range.base_address : pre_functions.back();
            auto next_address = after_functions.empty() ? m.details.range.base_address + m.details.range.size
                                                        : after_functions.front();
            // all ref address in range
            if (std::ranges::all_of(ref_addrs, [=](auto ref_addr) {
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
            fprintf(stderr, "%p discard the function\n", (void *) addr);
        }

        auto ret = sureFunctions | std::ranges::views::transform([](auto &p) { return p.first; }) |
                   ranges::to<std::vector>();
        ranges::sort(ret);
        for (int i = 1; i < ret.size(); ++i) {
            const auto cur = ret[i];
            const auto pre = ret[i - 1];
            if (ret[i] - ret[i - 1] > 0xfff) {

                continue;
            }
        }
        return ret;
    }

    void ScanCtx::scan() {
        const auto functions = pre_function();
        for (size_t i = 0; i < functions.size(); i++) {
            const auto address = functions[i];
            function_limit = known_functions.contains(address) && known_functions.at(address).size != 0 ?
                             known_functions[address].size + address :
                             (i + 1 == functions.size() ? 1 : functions[i + 1]);

#ifndef NDEBUG
            if (function_limit && known_functions.contains(address)) {
                const auto &func = known_functions[address];
                if (func.size)
                    assert(func.size + func.address == function_limit);
            }
#endif
            // maybe function_limit has some data
            if (!known_functions.contains(address)) {
                disasm dis{
                        std::span{(uint8_t *) address, function_limit - address}};
                auto max_function_limit = address;
                for (auto iter = dis.begin(), end = dis.end(); iter != end; ++iter) {
                    const auto &insn = *iter;
                    // break when data
                    if (rodatas.contains(insn.address)) {
                        max_function_limit = insn.address;
                        break;
                    }
                    max_function_limit = std::max((uintptr_t) iter.pre_insn.address, max_function_limit);
                }
                function_limit = std::min(max_function_limit, function_limit);
            }
            // function_limit is next function address
            function_limit--;
            scan_function(address);
        }
    }

    void ScanCtx::scan_function(uintptr_t address) {
        size_t index = 0;
        assert(cur == nullptr);
        cur = &m.functions.emplace_back(Function{address});
        cur->module = &m;
        cur_block = createBlock(address);
        disasm ds{(uint8_t *) address, text.base_address + text.size - address};
        uintptr_t next_insn_address;
        for (const auto &insn: ds) {
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
                            cur_block->consts.emplace_back(str);
                        }
                    }
                }
                    break;
                default:
                    if (insn.id >= X86_INS_JAE && insn.id <= X86_INS_JS) {
                        assert(x86_details.op_count == 1 &&
                               x86_details.operands[0].type == x86_op_type::X86_OP_IMM);
                        auto addr = static_cast<uint64_t>(x86_details.operands[0].imm);
                        function_limit = std::max((uintptr_t) addr, function_limit);

                        cur_block = createBlock(next_insn_address);
                    }
                    break;
            }
        }
        fprintf(stderr, "%s\n",
                fmt::format("address[{}] find new function limit:{}", address, next_insn_address).c_str());
        function_end(next_insn_address);
    }

    size_t ScanCtx::guess_function_size(const uintptr_t imm) const {
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
            } else if (insn->id == X86_INS_JMP || insn->id == X86_INS_RET || insn->id == X86_INS_RETFQ ||
                       insn->id == X86_INS_CALL) {
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
                            function_limit = std::max(static_cast<uintptr_t>(insn->address) + insn->size,
                                                      function_limit);
                        }
                    }
                } else if (insn->id == X86_INS_CALL) {
                    if (x86_details.operands[0].type == X86_OP_IMM) {
                        if (function_limit == insn->address) {
#ifdef __linux__
                            // is __stack_chk_fail?
                            auto target = x86_details.operands[0].imm;
                            static const auto __stack_chk_fail_address = gum_module_find_export_by_name(gum_process_get_libc_module(),
                                                                                                        "__stack_chk_fail");
                            if (__stack_chk_fail_address &&
                                address_is_lib_plt((uint8_t *) target, __stack_chk_fail_address))
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
                        auto jump_table = static_cast<fixed_type *>(guess_switch_jump_table_address(dis,
                                                                                                    switch_jump_table,
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
}