#include "ctx.hpp"
#include "config.hpp"
#include <filesystem>
#include <frida-gum.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace function_relocation {
    Ctx &get_ctx() {
        static Ctx ctx;
        return ctx;
    }

    bool init_ctx() {
        auto &ctx = get_ctx();
        if (ctx.hcs) {
            ++ctx.ref;
            return true;
        }
        cs_arch_register_x86();
        static_assert(sizeof(csh) == sizeof(uintptr_t));
        auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &ctx.hcs);
        if (ec != CS_ERR_OK)
            return false;
        cs_option(ctx.hcs, CS_OPT_DETAIL, CS_OPT_ON);
#ifndef __APPLE__
        const auto real_log_path = std::filesystem::absolute(gum_process_get_main_module()->path).parent_path() / log_path;
        std::filesystem::remove(real_log_path);
        auto logger = spdlog::create<spdlog::sinks::basic_file_sink_st>(logger_name, real_log_path.string());
#else
        auto logger = spdlog::create<spdlog::sinks::ansicolor_stderr_sink_st>(logger_name);
#endif
        ++ctx.ref;
        logger->info("init ctx");
        return true;
    }

    void deinit_ctx() {
        auto &ctx = get_ctx();
        --ctx.ref;
        if (ctx.ref.load() == 0) {
            cs_close(&ctx.hcs);
            ctx.hcs = 0;
        }
    }

}// namespace function_relocation