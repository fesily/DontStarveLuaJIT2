#include "MemorySignature.hpp"
#include "config.hpp"
#include "luajit_config.hpp"
#include "util/inlinehook.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"
#include <array>
#include <frida-gum.h>

template<typename T>
static void protect_memory_writer(T *addr, T val) {
    GumPageProtection prot;
    gum_memory_query_protection(addr, &prot);
    gum_mprotect(addr, sizeof(T), prot | GUM_PAGE_WRITE);
    *addr = val;
    gum_mprotect(addr, sizeof(T), prot);
};

float frame_time = 1.0 / 30;
static float *fps_ptr;
static function_relocation::MemorySignature set_notebook_mode{"F3 0F 11 89 D8 01 00 00", -0x3E};
static void set_notebook_mode_config_hook(void *) {}
extern bool DontStarveInjectorIsClient;
static function_relocation::MemorySignature set_notebook_mode_config{"80 B9 D4 01 00 00 00", -0x6};

auto main_module_path = [] { return gum_module_get_path(gum_process_get_main_module()); };

static bool find_set_notebook_mode_imm() {
    if (!DontStarveInjectorIsClient) {
        if (!set_notebook_mode_config.scan(main_module_path())) return false;
        //delete this mode
        Hook((uint8_t *) set_notebook_mode_config.target_address, (uint8_t *) &set_notebook_mode_config_hook);
    }
    if (set_notebook_mode.scan(main_module_path())) {
        function_relocation::disasm ds{(uint8_t *) set_notebook_mode.target_address, 256};
        int offset = 0;
        int movss[] = {
                1023969417,// 1/30
                1015580809,// 1/60
                1106247680,// 30.0
                1114636288,// 60.0
        };
        void *addrs[4];
        for (auto &&insn: ds) {
            if (insn.id != X86_INS_MOVSS) continue;
            if (insn.detail->x86.operands[0].type != x86_op_type::X86_OP_REG) continue;
            if (insn.detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) continue;
            if (insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM0 && insn.detail->x86.operands[0].reg != x86_reg::X86_REG_XMM1)
                return false;

            auto ptr = (int32_t *) function_relocation::read_operand_rip_mem(insn, insn.detail->x86.operands[1]);
            if (movss[offset] != *ptr) return false;
            addrs[offset] = (float *) insn.address;
            offset++;
            if (offset == 4)
                break;
        }
        GumAddressSpec spec{(void *) set_notebook_mode.target_address, INT_MAX / 2};
        float *ptr = (float *) gum_memory_allocate_near(&spec, 256, sizeof(void *), GUM_PAGE_RW);
        if (!ptr) return false;
        auto movss_writer = +[](void *addr, float *target) {
            // target = addr + 8 + offset
            auto offset = (int64_t) target - (int64_t) addr - 8;
            gum_mprotect(addr, 16, GUM_PAGE_RWX);
            *(((int32_t *) addr) + 1) = (int32_t) offset;
            gum_mprotect(addr, 16, GUM_PAGE_RX);
        };
        for (size_t i = 0; i < 4; i++) {
            movss_writer(addrs[i], ptr + i);
        }
        fps_ptr = ptr;
        auto new_val = (int *) fps_ptr;
        memcpy(new_val, movss, 4 * sizeof(int));
        return true;
    }
    return false;
}


static float *find_luaupdate_imm(function_relocation::MemorySignature &sign) {
    if (sign.scan(main_module_path())) {
        if (!sign.only_one) {
            sign.target_address = sign.targets.front();
            for (auto addr: sign.targets) {
                if (sign.target_address != addr)
                    return nullptr;
            }
        }
        auto insn = function_relocation::disasm::get_insn((uint8_t *) sign.target_address, 8 + 1);
        if (insn->detail->x86.operands[1].type != x86_op_type::X86_OP_MEM) return nullptr;
        auto imm = (int32_t *) function_relocation::read_operand_rip_mem(*insn, insn->detail->x86.operands[1]);
        if (0x3D088889 == *imm) {
            return (float *) imm;
        }
    }
    return nullptr;
}

static std::array<float *, 1> luaupdatefps;
static double *getticktimefps;
static function_relocation::MemorySignature luaupdate{"FF 83 C8 00 00 00 F3 0F 10 35", 6};
static function_relocation::MemorySignature getticktime{"00 00 00 20 11 11 A1 3F", 0};

static bool DS_LUAJIT_get_logic_fps() {
    getticktime.prot_flag = GUM_PAGE_READ;
    if (getticktime.scan(main_module_path())) {
        getticktimefps = (double *) getticktime.target_address;
    } else {
        return false;
    }
    //function_relocation::MemorySignature luaupdate1{"48 8D 43 70", 17};
    //function_relocation::MemorySignature luaupdate2{"B8 89 88 88 88", 4, false};
    luaupdatefps[0] = find_luaupdate_imm(luaupdate);
    return luaupdatefps[0];
}

extern "C" DONTSTARVEINJECTOR_API int DS_LUAJIT_set_target_fps(int fps, int tt) {
#ifndef _WIN32
    return -1;
#endif

    float val = 1.0f / (float) fps;
    float val2 = (float) fps;
    if (tt & 0b01) {
        static auto target_address = []() {
            return find_set_notebook_mode_imm();
        }();
        if (target_address) {
            auto old = fps_ptr[3];
            fps_ptr[1] = val;
            fps_ptr[3] = val2;
            frame_time = std::min(val, 1 / 30.0f);
            return old;
        }
    }
    if (tt & 0b10) {
        static bool init_flag = DS_LUAJIT_get_logic_fps();
        if (init_flag) {
            auto old = 1.0 / (*getticktimefps);
            if (*luaupdatefps[0] != val) {
                protect_memory_writer(getticktimefps, (double) val);
                protect_memory_writer(luaupdatefps[0], val);
            }
            return (int) ceil(old);
        }
    }
    return -1;
}

extern "C" DONTSTARVEINJECTOR_API int DS_LUAJIT_replace_client_network_tick(char tick) {
#ifndef _WIN32
    return 0;
#endif
    if (!DontStarveInjectorIsClient) return 0;

    static auto client_network_tick_addr = []() -> std::array<char *, 3> {
        function_relocation::MemorySignature client_network_tick = {"41 83 38 3C 49 0F 46 C0", 0};                     // < 60 then give tick
        function_relocation::MemorySignature default_client_network_tick_time = {"44 8D 76 64", 0x3};                  // 100ms
        function_relocation::MemorySignature default_client_network_tick_update_fps = {"41 BC 0A 00 00 00 85 D2", 0x2};// 10fps

        if (client_network_tick.scan(main_module_path()) && default_client_network_tick_time.scan(main_module_path()) && default_client_network_tick_update_fps.scan(main_module_path())) {
            auto b = (char *) client_network_tick.target_address;
            //"C7 00 0f 00 00 00 90 90" "mov [rax], 0xf;nop;nop";
            std::array<char, 8> patched{(char) 0xC7, (char) 0x00, (char) 0x0f, (char) 0x00, (char) 0x00, (char) 0x00, (char) 0x90, (char) 0x90};
            protect_memory_writer((std::array<char, 8> *) b, patched);
            auto b1 = (char *) default_client_network_tick_time.target_address;
            return {b + 2, b1, (char *) default_client_network_tick_update_fps.target_address};
        }
        return {};
    }();
    if (std::ranges::all_of(client_network_tick_addr, [](auto p) { return p; })) {
        tick = std::min<char>(120, tick);
        auto tick_time = (char) (int) (1000.0 / tick);
        protect_memory_writer(client_network_tick_addr[0], tick);
        protect_memory_writer(client_network_tick_addr[1], tick_time);
        protect_memory_writer(client_network_tick_addr[2], tick);
    }
    return 0;
}

extern "C" void LoadGameModConfig() {
    auto config = luajit_config::read_from_file();
    if (!config) return;
    auto logic_fps = (int)ceil(config->logic_fps);
    if (logic_fps > 30) {
        DS_LUAJIT_set_target_fps(logic_fps, 0b10);
    }
}