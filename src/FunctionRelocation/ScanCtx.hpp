#pragma once

#include "disasm.h"
#include "ModuleSections.hpp"

#include <algorithm>
#include <cassert>

namespace function_relocation {

    struct ScanCtx {
        ModuleSections &m;

        const GumMemoryRange text;

        ScanCtx(ModuleSections &_m, uintptr_t scan_address);


        Function *cur = nullptr;
        CodeBlock *cur_block = nullptr;
        uintptr_t function_limit = 0;
        // When non-zero, clamp function_limit so a Jcc cannot expand past the
        // discovered body size.
        uintptr_t body_hard_end = 0;

        void function_end(uintptr_t addr);

        CodeBlock *createBlock(uintptr_t addr) const;

        // Disasm one body into m.functions (creates or reuses Function at address).
        // function_limit must be set to last inclusive byte of the body first.
        void scan_function(uintptr_t address);

    };
}
