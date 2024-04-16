#include "ModuleSections.hpp"

#include <unordered_set>
#include <ranges>
#include <algorithm>
#include <cassert>

#ifdef _WIN32
#include <pe-parse/parse.h>
#else
#include <dlfcn.h>
#endif

#include <range/v3/all.hpp>

#include "ctx.hpp"

template<typename T>
size_t hash_vector(const std::vector<T> &vec) {
    auto seed = vec.size();
    for (const auto &v: vec) {
        seed ^= std::hash<T>{}(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
    }
    return seed;
}

template<>
struct std::hash<function_relocation::CodeBlock> {
    size_t operator()(const function_relocation::CodeBlock &block) noexcept {
        return hash_vector(block.consts);
    }
};

namespace function_relocation {
    using namespace std::literals;

    void *
    fix_func_address_by_signature(ModuleSections &target, const Function &original);

    bool ModuleSections::in_text(uintptr_t address) const {
        return text.base_address <= address && address <= text.base_address + text.size;
    }

    bool ModuleSections::in_plt(uintptr_t address) const {
        return plt.base_address <= address && address <= plt.base_address + plt.size;
    }

    bool ModuleSections::in_got_plt(uintptr_t address) const {
        return got_plt.base_address <= address && address <= got_plt.base_address + got_plt.size;
    }

    bool ModuleSections::in_rodata(uintptr_t address) const {
        return rodata.base_address <= address && address <= rodata.base_address + rodata.size;
    }

    ModuleSections::~ModuleSections() {
        if (details)
            gum_module_details_free(details);
    }

    static bool reg_is_ip(x86_reg reg) {
        return reg == x86_reg::X86_REG_RIP || reg == x86_reg::X86_REG_EIP || reg == x86_reg::X86_REG_IP;
    };

    static const char *read_data_string(const char *data) {
        constexpr auto data_limit = 16;
        if (!gum_memory_is_readable(data, data_limit))
            return nullptr;
        for (size_t i = 0; i < 256; i++) {
            if (!std::isprint((unsigned char)data[i]))
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
                if (op.type == x86_op_type::X86_OP_MEM) {
                    auto target = insn->address + insn->size + op.mem.disp;
                    if (m.in_got_plt(target)) {
                        imm = (intptr_t) *(void **) target;
                    }
                } else if (op.type == x86_op_type::X86_OP_IMM) {
                    imm = op.imm;
                }
            }
        }
        cs_free(insn, 1);
        return imm;
    }

    struct disasm {
        struct insn_release{
            constexpr void operator()(cs_insn* insn) {
                if (insn) 
                    cs_free(insn, 1); 
            }
        };
        using value_type = std::unique_ptr<cs_insn, insn_release>;
        using insn_type = value_type;

        struct iter {
            void operator++() {
                if (next())
                    --scan_insn_size;
                else {
                    left_buffer_length = 0;
                }
            }

            bool operator!=(const iter& end) noexcept{
                return !(scan_insn_size == 0 || left_buffer_length == 0);
            }

            cs_insn& operator*() {
                return *insn.get();
            }

            cs_insn* operator->() {
                return insn.get();
            }
            
            bool reset(uint8_t* addr) {
                const auto& buffer = self->buffer;
                if (addr < buffer.data() && addr > buffer.data()+buffer.size()) return false;
                next_buffer = addr;
                left_buffer_length = buffer.size() - (addr - buffer.data());
                next_addr = (uint64_t)addr;
                scan_insn_size = INT_MAX;
                return true;
            }

            bool next() {
                return cs_disasm_iter(self->hcs, &next_buffer, &left_buffer_length, &next_addr, insn.get());
            }

            disasm* self;
            insn_type insn;
            const uint8_t* next_buffer;
            size_t left_buffer_length;
            uint64_t next_addr;
            int scan_insn_size = INT_MAX;
        };

        disasm() = default;
        disasm(std::span<uint8_t> buff)
            : buffer{buff} {
            
        }
        iter begin() {
            auto ii = iter{this, malloc_insn(hcs)};
            ii.reset(buffer.data());
            ++ii;
            return ii;
        }
        iter end() {
            return {};
        }

        insn_type get_insn(void* addr) {
            if (addr < buffer.data() && addr > buffer.data()+buffer.size()) {
                return {};
            }
            auto size = buffer.size();
            auto code = (const uint8_t*)addr;
            auto insn = malloc_insn(hcs);
            if (!cs_disasm_iter(hcs, &code, &size, (uint64_t*)&addr, insn.get()))
                return {};
            return insn;
        }

        static insn_type malloc_insn(uintptr_t hcs){
            return insn_type{cs_malloc(hcs)};
        }
        uintptr_t hcs{get_ctx().hcs};
        std::span<uint8_t> buffer;
     
    };


    static uintptr_t read_operand_rip_mem(const cs_insn& insn, const cs_x86_op& op) {
        if (op.type != x86_op_type::X86_OP_MEM
            || !reg_is_ip(op.mem.base)
            || op.mem.segment != X86_REG_INVALID
            || op.mem.index != X86_REG_INVALID
            || op.mem.scale != 1)
            return 0;
        return op.mem.disp + insn.address + insn.size;
    }

    static bool address_is_lib_plt(uint8_t* address, uintptr_t target) {
        disasm dis {std::span{address, 8}};
        auto iter = dis.begin();
        const auto& insn = *iter;
        if (insn.id != X86_INS_JMP) 
            return false;
        const auto plt = *(uintptr_t*)read_operand_rip_mem(insn, insn.detail->x86.operands[0]);
        return plt == target;
    }

    static void* guess_switch_jump_table_address(disasm& dis, x86_reg switch_jump_table_reg, uintptr_t limit_address) {
        void* target = nullptr;
        for (const auto& insn : dis) {
            if (insn.address>=limit_address) return target;
            if (insn.id != X86_INS_MOV && insn.id != X86_INS_LEA) 
                continue;
            const auto& x86_details = insn.detail->x86;
            if (x86_details.disp == 0 ) continue;

            const auto& operand0= x86_details.operands[0];
            const auto& operand1= x86_details.operands[1];
            if (operand0.type == X86_OP_REG && operand0.reg == switch_jump_table_reg) {
                if (operand1.type == X86_OP_MEM && reg_is_ip(operand1.mem.base) &&  operand1.mem.index == x86_reg::X86_REG_INVALID &&
                        operand1.mem.segment == x86_reg::X86_REG_INVALID) {
                    target = (void*)(insn.address +insn.size + operand1.mem.disp);
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
        
        Function* find_known_function(uintptr_t address) {
            if (known_functions.contains(address))
                return &known_functions[address];
            uintptr_t match = 0;
            uintptr_t offset = std::numeric_limits<uintptr_t>::max();
            for (auto&[addr, func] : known_functions)
            {
                if (addr > address)
                    continue;
                if (address - addr < offset) {
                    offset = address - addr;
                    match = addr;
                }
            }
            return match ? &known_functions[match] : nullptr;
        }
        std::unordered_map<uintptr_t, size_t> function_sizes;
        std::unordered_map<uint64_t, size_t> sureFunctions;
        std::unordered_map<uint64_t, size_t> rodatas;

        auto pre_function(){
            std::unordered_map<uint64_t, size_t> maybeFunctions;

            for (const auto&[address, func] : known_functions){
                sureFunctions[address] = 1;
            }
            
            for (size_t index = 0; index < insns_count; ++index) {
                const auto &insn = insns[index];
                const auto next_insn_address = insn.address + insn.size;
                const auto &x86_details = insn.detail->x86;
                const auto &operand = x86_details.operands[0];
                const auto &operand1 = x86_details.operands[1];

                if (insn.id == X86_INS_JMP || insn.id == X86_INS_CALL) {
                    if (operand.type != x86_op_type::X86_OP_INVALID && operand.type != x86_op_type::X86_OP_REG) {
                        if (operand.type == x86_op_type::X86_OP_MEM && operand.reg != x86_reg::X86_REG_RIP)
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
                                maybeFunctions[imm]++;
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
                    if (operand.type == X86_OP_REG  && operand1.type == X86_OP_MEM) {
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
                    fprintf(stderr, "%s guess func size failed: %lo guess %lo\n", func.name.c_str(), func.size, guess_size);
                }
            } 
#endif
            for (auto& [addr, ref_count] : maybeFunctions | ranges::views::filter([&](const auto& pair)  {
                const auto& [addr,_] = pair;
                return !sureFunctions.contains(addr);
            }))
            {
                auto sureFuncs = sureFunctions | std::ranges::views::filter([addr](auto& ipair){return ipair.first<=addr;}) | std::ranges::views::transform([](auto& ipair){return ipair.first;}) | ranges::to<std::vector>();
                std::ranges::sort(sureFuncs);
                // maybe jmp self function 
                auto near_address = *std::ranges::min_element(sureFuncs, [addr](auto l, auto r){
                    return addr-l < addr-r;
                });
                auto func = find_known_function(near_address);
                if (func) {
                    function_sizes[addr] = func->size;
                    if (addr >= func->size + func->address) {
                        sureFunctions[addr] += ref_count;
                        continue;
                    }
                }
                if (!function_sizes.contains(near_address)) {
                    function_sizes[near_address] = guess_function_size(near_address);
                }
                auto length = function_sizes[near_address]; 
                if (addr >= near_address + length) {
                    sureFunctions[addr] += ref_count;
                    continue;
                }
                //fprintf(stderr, "%p discard the function\n", (void*)addr);
            }
            
            auto ret = sureFunctions | std::ranges::views::transform([](auto& p){return p.first;}) | ranges::to<std::vector>();
            ranges::sort(ret);
            return ret;
        }

        void scan() {
            const auto functions = pre_function();
            for (size_t i = 0; i < functions.size(); i++)
            {
                const auto address = functions[i];
                auto limit1 = function_sizes.contains(address)? function_sizes[address] + address : 0;
                auto limit2 = i+1 == functions.size() ? 0: functions[i+1];
                function_limit = limit1 != 0 ? std::min(limit1, limit2) : limit2;

                #ifndef NDEBUG
                if (function_limit && known_functions.contains(address)){
                    const auto& func = known_functions[address];
                    if (func.size)
                    assert(func.size + func.address +16 >= function_limit);
                }
                #endif

                if (!scan_function(address)){
                    fprintf(stderr, "can't find address at insns:%p", (void*)address);
                }
            }
        }

        bool scan_function(uintptr_t address) {
            size_t index = 0; 
            for (;index < insns_count; ++index) {
                if (insns[index].address == address)
                    break;
            }
            if (index == insns_count)
                return false;
            assert(cur == nullptr);
            cur = &m.functions.emplace_back(Function{address});
            cur->module = &m;
            cur_block = createBlock(address);
            for (;index < insns_count; ++index) {
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
                        if (operand.type != x86_op_type::X86_OP_INVALID && operand.type != x86_op_type::X86_OP_REG) {
                            if (operand.type == x86_op_type::X86_OP_MEM && !reg_is_ip(operand.mem.base))
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
                        if (insn.id != X86_INS_JMP) {
                            break;
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
                        if (x86_details.operands[1].type == x86_op_type::X86_OP_IMM) {
                            cur_block->const_numbers.push_back(x86_details.operands[1].imm);
                        }
                        break;
                    case X86_INS_MOV:
                    case X86_INS_LEA: {
                        if (x86_details.op_count == 2) {
                            if (x86_details.disp != 0) {
                                const auto is_offset = ((x86_details.operands[1].type == x86_op_type::X86_OP_MEM &&
                                  !reg_is_ip(x86_details.operands[1].mem.base)) ||
                                 (x86_details.operands[0].type == x86_op_type::X86_OP_MEM &&
                                  !reg_is_ip(x86_details.operands[0].mem.base)));
                                if (is_offset)
                                    cur_block->const_offset_numbers.emplace_back(x86_details.disp);
                                else
                                    cur_block->remote_rip_memory_count++;
                            }
                                
                            else if (x86_details.operands[1].type == X86_OP_IMM)
                                cur_block->const_numbers.emplace_back(x86_details.operands[1].imm);
                        }
                        const char *str = nullptr;
                        if (x86_details.op_count == 2 && x86_details.operands[0].type == x86_op_type::X86_OP_REG) {
                            const auto &op = x86_details.operands[1];
                            if (insn.id == X86_INS_LEA) {
                                if (op.type == x86_op_type::X86_OP_MEM && reg_is_ip(op.mem.base) &&
                                    op.mem.index == x86_reg::X86_REG_INVALID &&
                                    op.mem.segment == x86_reg::X86_REG_INVALID) {
                                    auto target = next_insn_address + op.mem.disp;
                                    if (m.in_rodata(target))
                                        str = read_data_string((char *) target);
                                }
                            } else if (insn.id == X86_INS_MOV) {
                                if (op.type == x86_op_type::X86_OP_IMM) {
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
                            auto addr = (uint64_t) x86_details.operands[0].imm;
                            function_limit = std::max(addr, function_limit);

                            cur_block = createBlock(next_insn_address);
                        }
                        break;
                }
            }
            return false;
        }
    // can't resolve:
    // 1. no stack frame function 
    // 2. jmp no short
    size_t guess_function_size(const uintptr_t imm) {
        uintptr_t function_limit = 0;
        x86_reg switch_target_reg = X86_REG_INVALID;
        auto dis = disasm(std::span{(uint8_t*)imm, size_t(-1)});
        for (const auto& insn_ref : dis) {
            auto insn = &insn_ref;
            const auto& x86_details = insn->detail->x86;
            if (insn->id >= X86_INS_JAE && insn->id <= X86_INS_JS) {
                assert(x86_details.op_count == 1 &&
                        x86_details.operands[0].type == x86_op_type::X86_OP_IMM);
                auto target_addr = (uint64_t) x86_details.operands[0].imm;
                function_limit = std::max(target_addr, function_limit);
            }else if (insn->id == X86_INS_JMP || insn->id == X86_INS_RET || insn->id == X86_INS_RETFQ) {
                if (insn->id == X86_INS_JMP) {
                    if (x86_details.operands[0].type == X86_OP_IMM && insn->size == 2) {
                        // shot jmp
                        const uintptr_t jump_target = x86_details.operands[0].imm;
                        const auto offset = jump_target - (insn->address+insn->size);
                        if (offset <= 255) {
                            function_limit = std::max(jump_target, function_limit);
                        }
                    }
                    if ( x86_details.operands[0].type == x86_op_type::X86_OP_MEM) {
                        const auto& operand = x86_details.operands[0];
                        if (operand.mem.disp != 0) {
                            // jmp switch table
                            constexpr auto fixed_scale = sizeof(void*)/sizeof(char);
                            using fixed_type = uint64_t;
                            
                            if (operand.mem.scale == fixed_scale && operand.mem.segment == X86_REG_INVALID && operand.mem.index == X86_REG_INVALID) {
                                const auto jump_table = (fixed_type*) operand.mem.disp;
                                if (m.in_rodata((uintptr_t)jump_table)) {
                                    while (1) {
                                        const auto jump_target = (uintptr_t)*jump_table;
                                        if (!m.in_text(jump_target))
                                            break;
                                        function_limit = std::max(jump_target, function_limit);
                                    }
                                }
                            }
                            
                        }
                    }
                    else if (x86_details.operands[0].type == X86_OP_REG) {
                        if (x86_details.operands[0].reg == switch_target_reg) {
                            // switch jump
                            function_limit = std::max(insn->address + insn->size, function_limit);
                        }
                    }
                }
                if (function_limit < insn->address + insn->size) {
                    return insn->address + insn->size - imm;
                }
            }else if (insn->id == X86_INS_MOVSXD) {
                // maybe load switch
                if (x86_details.operands[0].type == x86_op_type::X86_OP_REG) {
                    const auto& operand = x86_details.operands[1];
                    constexpr auto fixed_scale = sizeof(void*)/sizeof(char)/2;
                    using fixed_type = int32_t;
                    if (operand.type == x86_op_type::X86_OP_MEM
                        && operand.mem.scale == fixed_scale) {
                        auto switch_jump_table = operand.mem.base;
                        auto jump_table = (fixed_type*) guess_switch_jump_table_address(dis, switch_jump_table, insn->address);
                        if (jump_table && m.in_rodata((uintptr_t)jump_table)) {
                            switch_target_reg = x86_details.operands[0].reg;
                            auto offset_table = jump_table;
                            assert(rodatas.contains((uintptr_t)jump_table));
                            uintptr_t jump_target = 0;
                            for (int i =0;i<9999;i++){
                                const auto offset = (*offset_table);
                                const auto real_address = (uintptr_t)jump_table + offset;
                                if (!m.in_text(real_address))
                                    break;
                                jump_target = std::max(real_address, jump_target);
                                offset_table++;
                                if (rodatas.contains((uintptr_t)offset_table))
                                    break;
                            }
                            function_limit = std::max(jump_target, function_limit);
                        }
                    }
                }
            }else if (insn->id == X86_INS_CALL) {
                if (x86_details.operands[0].type == x86_op_type::X86_OP_IMM) {
                    if (function_limit == insn->address) {
                        // is __stack_chk_fail? 
                        auto target = x86_details.operands[0].imm;
                        static const auto __stack_chk_fail_address = gum_module_find_export_by_name("libc.so.6", "__stack_chk_fail");
                        if (__stack_chk_fail_address && address_is_lib_plt((uint8_t*)target, __stack_chk_fail_address))
                            return insn->address + insn->size - imm;
                    }
                    
                    // is end call?
                    // next is nop or push
                    for (auto& insn_next : disasm{std::span{(uint8_t*)insn->address+insn->size, sizeof(void*)*2*2}}) {
                        if (insn_next.id == X86_INS_NOP ) continue; 
                        else if( insn_next.id == X86_INS_PUSH) {
                            return insn->address + insn->size - imm;
                        }else{
                            break;
                        }
                    }
                }
            }
        }
        return 0;
    }

    };

    static GumModuleDetails *get_module_details(const char *path) {
        if (path == nullptr) {
            return gum_module_details_copy(gum_process_get_main_module());
        }
        GumModuleDetails *out_details;
        auto fn = [&](const GumModuleDetails *details) -> gboolean {
            if (strcmp(details->path, path) == 0
                || std::string_view(details->path).ends_with(path)) {
                out_details = gum_module_details_copy(details);
                return FALSE;
            }
            return TRUE;
        };
        gum_process_enumerate_modules(+[](const GumModuleDetails *details,
                                          gpointer user_data) -> gboolean {
            return (*static_cast<decltype(fn) *>(user_data))(details);
        }, (void *) &fn);
        return out_details;
    }

    static ModuleSections get_module_sections(const char *path) {
        const auto details = get_module_details(path);
        ModuleSections sections{};
#ifdef _WIN32
        const auto pe = peparse::ParsePEFromFile(details->path);
        if (pe)
        {
            auto args = std::tuple{&sections, details->range->base_address};
            peparse::IterSec(pe, +[](void* user_data,
                const peparse::VA& secBase,
                const std::string& secName,
                const peparse::image_section_header& s,
                const peparse::bounded_buffer* data)
                {
                    auto& [sections, base_address] = *(decltype(args)*)user_data;
                    auto real_address = s.VirtualAddress + base_address;
                    auto len = data->bufLen;
                    if (secName == ".text")
                        sections->text = { real_address, len };
                    else if (secName == ".rdata")
                        sections->rodata = { real_address, len };
                    return 0;
                }, (void*)&args);
            peparse::DestructParsedPE(pe);
        }
#else

        gum_module_enumerate_sections(path, +[](const GumSectionDetails *details, gpointer user_data) -> gboolean {
            if (details->name == ".text"sv)
                (*(ModuleSections *) user_data).text = {details->address, details->size};
            else if (details->name == ".rodata"sv)
                (*(ModuleSections *) user_data).rodata = {details->address, details->size};
            else if (details->name == ".plt"sv)
                (*(ModuleSections *) user_data).plt = {details->address, details->size};
            else if (details->name == ".got.plt"sv)
                (*(ModuleSections *) user_data).got_plt = {details->address, details->size};
            return TRUE;
        }, (void *) &sections);
#endif
        sections.details = details;
        return sections;
    }


    ModuleSections init_module_signature(const char *path, uintptr_t scan_start_address) {
        auto sections = get_module_sections(path);
        ScanCtx ctx{sections, scan_start_address};
         // try get the function name by debug info
        #ifndef _WIN32
        gum_module_enumerate_symbols(path, +[](const GumSymbolDetails* details, gpointer data)->gboolean{
            if (details->type == GUM_SYMBOL_FUNCTION || details->type == GUM_SYMBOL_OBJECT) {
                const auto ptr = (decltype(ctx)*)data;
                if (ptr->m.in_text(details->address))
                    ptr->known_functions.try_emplace(details->address, Function{.address=details->address, .size=(size_t)details->size, .name=details->name} );
            }
            return true;
        },&ctx);
        #endif
        ctx.scan();
        for (const auto& [address, func] : ctx.known_functions)
            sections.known_functions[address] = func.name;
        
        for (auto &func: sections.functions) {
#if 1
            if (!sections.known_functions.contains(func.address))
                fprintf(stderr, "unkown ptr: %p\n", (void*)func.address);            
#endif
            for (const auto &block: func.blocks) {
                for (const auto &c: block.consts) {
                    if (c->ref == 1 && (func.const_key == nullptr || c->value.size() > func.const_key->size())) {
                        func.const_key = &c->value;
                    }
                }
            }

            func.consts_hash = hash_vector(func.blocks);
        }
        return sections;
    }


    struct MatchConfig {
        const float consts_score = 2;
        const float call_score = 1;
        const float const_numbers_score = 0.8;
        const float const_offset_score = 0.2;

        int string_huge_limit = 48;
        int string_huge_group = 1;
        int string_long_limit = 24;
        int string_long_group = 2;
        int string_medium_limit = 16;
        int string_medium_group = 3;
        int const_complex_limit = 16;
        int const_complex_group = 1;
        const float match_score = 999;
    };

    struct FunctionMatchCtx {
        struct Match {
            const Function *matched;
            float score;

            operator bool() const {
                return matched != nullptr;
            }
        };

        ModuleSections &sections;

        MatchConfig &config;

        std::vector<Match> match_function(std::string_view key) {
            return sections.functions | std::views::filter([key](const auto &function) {
                if (*function.const_key == key)
                    return true;
                auto block = std::ranges::find_if(function.blocks, [key](const auto &v) {
                    return std::ranges::find_if(v.consts, [key](const auto &c) {
                        return c->value == key;
                    }) != v.consts.end();
                });
                return block != function.blocks.end();
            }) | std::views::transform([this](const auto &function) {
                return Match{&function, config.match_score};
            }) | ranges::to<std::vector>();
        }

        std::vector<Match> match_function(const Function &func1) {
            const auto target = func1.consts_hash;
            std::vector<Match> res;
            for (auto &func: sections.functions) {
                if (target == func.consts_hash)
                    res.emplace_back(Match{&func, config.match_score});
            }
            return res;
        }

        Match match_function_search(const Function &func) {
            float max = 0;
            const CodeBlock *maybeBlock = nullptr;
            for (const auto &fn: sections.functions) {
                for (const auto &block: fn.blocks) {
                    for (const auto &target_block: func.blocks) {
                        auto score = calc_match_score(block, target_block);
                        if (score > max) {
                            maybeBlock = &block;
                            max = score;
                        }
                    }
                }
            }
            return Match{maybeBlock->function, max};
        };

        auto known_functions(const CodeBlock &block) {
            std::vector known1 = block.call_functions | std::views::transform([this](const auto &addr) {
                auto iter = sections.known_functions.find(addr);
                return iter != sections.known_functions.end() ? iter->second : std::string_view{};
            }) | std::views::filter([](const auto &v) { return !v.empty(); }) | ranges::to<std::vector>();
            return known1;
        }

        float calc_match_score(const CodeBlock &block, const CodeBlock &target_block) {
            std::vector<Const *> intersectionConst;

            std::ranges::set_intersection(block.consts, target_block.consts,
                                          std::back_inserter(intersectionConst));

            if (!target_block.consts.empty() && intersectionConst.empty()) {
                return {};
            }
            std::vector<uint64_t> intersectionNumber;
            std::ranges::set_intersection(block.const_numbers, target_block.const_numbers,
                                          std::back_inserter(intersectionNumber));
            if (!target_block.const_numbers.empty() && intersectionNumber.empty()) {
                return {};
            }
            std::vector<uint64_t> intersectionOffNumber;
            std::ranges::set_intersection(block.const_offset_numbers, target_block.const_numbers,
                                          std::back_inserter(intersectionOffNumber));
            if (!target_block.const_offset_numbers.empty() && intersectionOffNumber.empty()) {
                return {};
            }
            std::vector<std::string_view> intersectionCall;
            auto known = known_functions(target_block);
            auto known1 = known_functions(block);
            std::ranges::set_intersection(known, known1,
                                          std::back_inserter(intersectionCall));

            if (!known.empty() && intersectionCall.empty()) {
                return {};
            }

            return intersectionConst.size() * config.consts_score +
                   intersectionNumber.size() * config.const_numbers_score +
                   intersectionOffNumber.size() * config.const_offset_score +
                   intersectionCall.size() * config.call_score;
        }


        const CodeBlock &max_block(const Function &func) {
            return *std::ranges::max_element(func.blocks, [this](auto &l, auto &r) {
                return calc_score(l) > calc_score(r);
            });
        }

        float calc_score(const CodeBlock &block) {
            return block.consts.size() * config.consts_score + block.call_functions.size() * config.call_score +
                   block.const_numbers.size() * config.const_numbers_score;
        }
    };

    static float calc_score(const Function &func, const MatchConfig &config) {
        float res = 0;
        for (const auto &block: func.blocks) {
            res += block.consts.size() * config.consts_score + block.call_functions.size() * config.call_score +
                   block.const_numbers.size() * config.const_numbers_score;
        }
        return res;
    }

    uintptr_t ModuleSections::try_fix_func_address(const Function &original, uint64_t maybe_addr) {
        MatchConfig config;
        FunctionMatchCtx ctx{*this, config};
        const auto targetScore = calc_score(original, config);
        if (original.const_key != nullptr) {
            auto matched = ctx.match_function(*original.const_key);
            assert(matched.size() <= 1);
            if (matched.size() == 1) {
                return matched[0].matched->address;
            }
        } else {
            auto matched = ctx.match_function_search(original);
            if (matched && matched.score > targetScore * 0.95) {
                return matched.matched->address;
            }
        }
        return (uintptr_t) fix_func_address_by_signature(*this, original);
    }

}
