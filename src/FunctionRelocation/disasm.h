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
                    left_buffer_length = 0;
                }
            }

            bool operator!=(const iter &end) noexcept {
                return !(scan_insn_size == 0 || left_buffer_length == 0);
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
                next_buffer = addr;
                left_buffer_length = buffer.size() - (addr - buffer.data());
                next_addr = (uint64_t) addr;
                scan_insn_size = INT_MAX;
                return true;
            }

            bool next() {
                return cs_disasm_iter(self->hcs, &next_buffer, &left_buffer_length, &next_addr, insn.get());
            }

            disasm *self;
            insn_type insn;
            const uint8_t *next_buffer;
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

        insn_type get_insn(void *addr) {
            if (addr < buffer.data() && addr > buffer.data() + buffer.size()) {
                return {};
            }
            auto size = buffer.size();
            auto code = static_cast<const uint8_t*>(addr);
            auto insn = malloc_insn(hcs);
            if (!cs_disasm_iter(hcs, &code, &size, (uint64_t * ) & addr, insn.get()))
                return {};
            return insn;
        }

        static insn_type malloc_insn(uintptr_t hcs) {
            return insn_type{cs_malloc(hcs)};
        }

        uintptr_t hcs{get_ctx().hcs};
        std::span<uint8_t> buffer;

    };
}
#endif //DONTSTARVELUAJIT_DISASM_H
