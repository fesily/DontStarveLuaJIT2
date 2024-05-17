#pragma once

#include "disasm.h"
#include "ModuleSections.hpp"

#include <vector>
#include <ranges>
#include <range/v3/all.hpp>
#include <algorithm>
#include <cassert>
#include <format>
#include <list>

namespace function_relocation {

    struct ScanCtx {
        ModuleSections &m;

        std::unordered_map<uintptr_t, Function> known_functions;
        const GumMemoryRange text;

        ScanCtx(ModuleSections &_m, uint64_t scan_address);


        Function *cur = nullptr;
        CodeBlock *cur_block = nullptr;
        uint64_t function_limit = 0;

        void function_end(uint64_t addr);

        CodeBlock *createBlock(uint64_t addr) const;

        Function *find_known_function(uintptr_t address);
        std::unordered_map<uint64_t, size_t> sureFunctions;
        std::unordered_map<uint64_t, size_t> rodatas;

        uintptr_t scan_switch_case_rodata(uintptr_t address, x86_reg reg, const std::list<uintptr_t> &case_address, uintptr_t max_address);

        uintptr_t guess_pre_jump_table_length(uintptr_t target, uint64_t pre_disp);

        uintptr_t guess_jump_table_length(uintptr_t target, uint64_t disp, std::list<uintptr_t> &case_address);

        std::vector<uintptr_t> pre_function();

        void scan();

        void scan_function(uintptr_t address);

        size_t guess_function_size(const uintptr_t imm) const;

    };

}