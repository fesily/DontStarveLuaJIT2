#include "ctx.hpp"
#include <frida-gum.h>
#include <filesystem>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>
#include "config.hpp"
namespace function_relocation {
    Ctx &get_ctx() {
        static Ctx ctx;
        return ctx;
    }

    bool init_ctx() {
        if (get_ctx().hcs)
            return true;
        cs_arch_register_x86();
        static_assert(sizeof(csh) == sizeof(uintptr_t));
        auto ec = cs_open(CS_ARCH_X86, CS_MODE_64, &get_ctx().hcs);
        if (ec != CS_ERR_OK)
            return false;
        cs_option(get_ctx().hcs, CS_OPT_DETAIL, CS_OPT_ON);
        std::filesystem::remove(log_path);
        spdlog::create<spdlog::sinks::basic_file_sink_st>(logger_name, log_path);
        return true;
    }

    void deinit_ctx() {
        cs_close(&get_ctx().hcs);
        get_ctx().hcs = 0;
    }

}