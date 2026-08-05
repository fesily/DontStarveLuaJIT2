// plugin_fps_render — DS_LUAJIT_set_target_fps / get_frame_time_s
#include "config.hpp"
#include "MemorySignature.hpp"
#include "util/inlinehook.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"

#include <algorithm>
#include <cstring>
#include <frida-gum.h>

#ifdef _WIN32
#define NOMINMAX
#include <Windows.h>
#endif

namespace {

float g_frame_time_s = 1.0f / 30.0f;
float *fps_ptr = nullptr;
function_relocation::MemorySignature set_notebook_mode{"F3 0F 11 89 D8 01 00 00", -0x3E};
void set_notebook_mode_config_hook(void *) {}
function_relocation::MemorySignature set_notebook_mode_config{"80 B9 D4 01 00 00 00", -0x6};

const char *main_module_path() {
    return gum_module_get_path(gum_process_get_main_module());
}

bool find_set_notebook_mode_imm() {
#ifdef _WIN32
    if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
        if (!set_notebook_mode_config.scan(main_module_path())) {
            return false;
        }
        Hook((uint8_t *)set_notebook_mode_config.target_address,
             (uint8_t *)&set_notebook_mode_config_hook);
    }
    if (!set_notebook_mode.scan(main_module_path())) {
        return false;
    }
    function_relocation::disasm ds{(uint8_t *)set_notebook_mode.target_address, 256};
    int offset = 0;
    int movss[] = {
        1023969417, // 1/30
        1015580809, // 1/60
        1106247680, // 30.0
        1114636288, // 60.0
    };
    void *addrs[4];
    for (auto &&insn : ds) {
        if (insn.id != X86_INS_MOVSS) {
            continue;
        }
        if (insn.detail->x86.operands[0].type != x86_op_type::X86_OP_REG) {
            continue;
        }
        if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) {
            continue;
        }
        if (insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM0 &&
            insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM1) {
            return false;
        }
        auto ptr = (int32_t *)function_relocation::read_operand_rip_mem(insn, insn.detail->x86.operands[1]);
        if (movss[offset] != *ptr) {
            return false;
        }
        addrs[offset] = (float *)insn.address;
        offset++;
        if (offset == 4) {
            break;
        }
    }
    GumAddressSpec spec{(void *)set_notebook_mode.target_address, INT_MAX / 2};
    float *ptr = (float *)gum_memory_allocate_near(&spec, 256, sizeof(void *), GUM_PAGE_RW);
    if (!ptr) {
        return false;
    }
    auto movss_writer = +[](void *addr, float *target) {
        auto offset = (int64_t)target - (int64_t)addr - 8;
        gum_mprotect(addr, 16, GUM_PAGE_RWX);
        *(((int32_t *)addr) + 1) = (int32_t)offset;
        gum_mprotect(addr, 16, GUM_PAGE_RX);
    };
    for (size_t i = 0; i < 4; i++) {
        movss_writer(addrs[i], ptr + i);
    }
    fps_ptr = ptr;
    memcpy((int *)fps_ptr, movss, 4 * sizeof(int));
    return true;
#else
    return false;
#endif
}

} // namespace

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_set_target_fps(int fps, int tt) {
#ifndef _WIN32
    (void)fps;
    (void)tt;
    return -1;
#else
    if (fps <= 0) {
        return -1;
    }
    if (tt & 0b01) {
        static auto target_address = []() { return find_set_notebook_mode_imm(); }();
        float val = 1.0f / (float)fps;
        float val2 = (float)fps;
        if (target_address && fps_ptr) {
            auto old = fps_ptr[3];
            fps_ptr[1] = val;
            fps_ptr[3] = val2;
            g_frame_time_s = std::min(val, 1.0f / 30.0f);
            return static_cast<int>(old);
        }
    }
    return -1;
#endif
}

DONTSTARVEINJECTOR_GAME_API float DS_LUAJIT_get_frame_time_s(void) {
    return g_frame_time_s;
}
