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
        // When non-zero, clamp function_limit so Jcc cannot expand past Nucleus size.
        uintptr_t body_hard_end = 0;

        void function_end(uintptr_t addr);

        CodeBlock *createBlock(uintptr_t addr) const;

        Function *find_known_function(uintptr_t address);

        std::unordered_map<uintptr_t, size_t> sureFunctions;
        std::unordered_map<uintptr_t, size_t> rodatas;
        std::unordered_map<uintptr_t, size_t> authoritative_sizes; // start -> size from pdata


        // Legacy CALL/FDE/ret heuristic boundary discovery. Prefer
        // scan_nucleus_bodies() when FunctionTable is authoritative.
        std::vector<uintptr_t> pre_function();

        void scan();

        // Disasm one body into m.functions (creates or reuses Function at address).
        // function_limit must be set to last inclusive byte of the body first.
        void scan_function(uintptr_t address);

        // Scan features for every Function already on m with size>0.
        // Uses Function::size as the sole body length (Nucleus-backed).
        void scan_nucleus_bodies();

        size_t guess_function_size(const uintptr_t imm) const;

    };
}