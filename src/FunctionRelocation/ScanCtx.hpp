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
#include <set>

namespace function_relocation {

    struct ScanCtx {
        ModuleSections &m;

        std::unordered_map<uintptr_t, Function> known_functions;
        const GumMemoryRange text;

        ScanCtx(ModuleSections &_m, uintptr_t scan_address);


        Function *cur = nullptr;
        CodeBlock *cur_block = nullptr;
        uintptr_t function_limit = 0;

        void function_end(uintptr_t addr);

        CodeBlock *createBlock(uintptr_t addr) const;

        Function *find_known_function(uintptr_t address);

        std::unordered_map<uintptr_t, size_t> sureFunctions;
        std::unordered_map<uintptr_t, size_t> rodatas;

        std::vector<uintptr_t> pre_function();

        void scan();

        void scan_function(uintptr_t address);

        size_t guess_function_size(const uintptr_t imm) const;

    };
}