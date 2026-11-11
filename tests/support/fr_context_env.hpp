#pragma once
// Process-wide frida-gum + FunctionRelocation context for the relocation tests
// that decode real modules (xref_pattern, graph_seed, unique_signature,
// net_stats_decode, eh_frame_starts, elf_plt_symbols).
//
// Usage: start every test case that decodes a module with
//
//     REQUIRE(ensure_reloc_context());
//
// function_relocation::init_ctx() is refcounted on a live capstone handle and
// deinit_ctx() does not remove the spdlog logger it registered, so a second
// init after shutdown fails with a duplicate-logger error. The environment is
// therefore created once per process, on the first test case that asks for it
// (never at static-initialization time), and torn down once at normal exit.
// A partial failure cleans up only the stage it actually completed.
#include "ctx.hpp"

#include <frida-gum.h>

#include <cstdio>
#include <exception>

namespace ds_test_detail {

    class RelocContextEnv {
    public:
        RelocContextEnv() {
            gum_init_embedded();
            gum_ready_ = true;
            try {
                ctx_ready_ = function_relocation::init_ctx();
            } catch (const std::exception &e) {
                std::fprintf(stderr, "function_relocation::init_ctx threw: %s\n", e.what());
                ctx_ready_ = false;
            }
            if (!ctx_ready_) {
                gum_deinit_embedded();
                gum_ready_ = false;
            }
        }

        ~RelocContextEnv() {
            if (ctx_ready_) {
                function_relocation::deinit_ctx();
            }
            if (gum_ready_) {
                gum_deinit_embedded();
            }
        }

        RelocContextEnv(const RelocContextEnv &) = delete;
        RelocContextEnv &operator=(const RelocContextEnv &) = delete;

        bool ready() const { return ctx_ready_; }

    private:
        bool gum_ready_ = false;
        bool ctx_ready_ = false;
    };

}// namespace ds_test_detail

// True when gum and the relocation ctx were (or already had been) initialized.
inline bool ensure_reloc_context() {
    static ds_test_detail::RelocContextEnv env;
    return env.ready();
}
