//
// Created by fesil on 24-4-16.
//
#pragma once
#ifndef DONTSTARVELUAJIT_DISASM_H
#define DONTSTARVELUAJIT_DISASM_H
#include <memory>
#include <span>
#include <frida-gum.h>

#include "ctx.hpp"
namespace function_relocation {
    struct disasm {
        struct insn_release {
            constexpr void operator()(cs_insn *insn) {
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
                    scan_insn_size = 0;
                }
            }

            bool operator!=(const iter &end) noexcept {
                return !(scan_insn_size == 0);
            }

            cs_insn &operator*() {
                return *insn.get();
            }

            cs_insn *operator->() {
                return insn.get();
            }

            bool reset(uint8_t *addr) {
                const auto &buffer = self->buffer;
                if (addr < buffer.data() && addr > buffer.data() + buffer.size()) return false;
                this->buffer = addr;
                next_buffer = addr;
                left_buffer_length = buffer.size() - (addr - buffer.data());
                next_addr = (uint64_t) addr;
                scan_insn_size = INT_MAX;
                return true;
            }

            bool next() {
                if (buffer != next_buffer) {
                    pre_insn = *insn;
                }
                return cs_disasm_iter(self->hcs, &next_buffer, &left_buffer_length, &next_addr, insn.get());
            }

            disasm *self;
            insn_type insn{};
            const uint8_t *buffer;
            const uint8_t *next_buffer;
            size_t left_buffer_length;
            uint64_t next_addr;
            int scan_insn_size = INT_MAX;
            cs_insn pre_insn{};
        };

        disasm() = default;

        disasm(std::span<uint8_t> buff)
                : buffer{buff} {

        }
        disasm(uint8_t *b, size_t length) : disasm(std::span{b, length}){
            
        }
        disasm(uint8_t* b, const GumMemoryRange& text) : disasm(b, text.base_address+text.size-reinterpret_cast<uintptr_t>(b)) {
            
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

        static insn_type get_insn(void *addr, size_t size) {
            auto code = static_cast<const uint8_t*>(addr);
            const auto hcs  = get_ctx().hcs;
            auto insn = malloc_insn(hcs);
            if (!cs_disasm_iter(hcs, &code, &size, (uint64_t * ) & addr, insn.get()))
                return {};
            return insn;
        }

        static insn_type get_pre_insn(void* addr) {
            const auto begin = (char*)addr - 16;
            for (int i = 0; i < 16; ++i) {
                auto insn = get_insn(begin, 32);
                if (insn && insn->address + insn->size == (uintptr_t )addr) {
                    return insn;
                }
            }
            return nullptr;
        }

        static insn_type malloc_insn(uintptr_t hcs) {
            return insn_type{cs_malloc(hcs)};
        }

        uintptr_t hcs{get_ctx().hcs};
        std::span<uint8_t> buffer;

    };
    
    inline bool reg_is_ip(x86_reg reg) {
        return reg == X86_REG_RIP || reg == X86_REG_EIP || reg == X86_REG_IP;
    };

    inline uintptr_t read_operand_rip_mem(const cs_insn &insn, const cs_x86_op &op) {
        if (op.type != X86_OP_MEM || !reg_is_ip(op.mem.base) || op.mem.segment != X86_REG_INVALID ||
            op.mem.index != X86_REG_INVALID || op.mem.scale != 1)
            return 0;
        return op.mem.disp + insn.address + insn.size;
    }
}
#endif //DONTSTARVELUAJIT_DISASM_H
