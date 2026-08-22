// plugin_network_tick — DS_LUAJIT_replace_network_tick
#include "config/InjectorHostConfig.hpp"
#include "MemorySignature.hpp"
#include "disasm.h"
#include "ScanCtx.hpp"

#include <algorithm>
#include <array>
#include <frida-gum.h>

namespace {

template <typename T>
void protect_memory_writer(T *addr, T val) {
    GumPageProtection prot;
    gum_memory_query_protection(addr, &prot);
    gum_mprotect(addr, sizeof(T), prot | GUM_PAGE_WRITE);
    *addr = val;
    gum_mprotect(addr, sizeof(T), prot);
}

const char *main_module_path() {
    return gum_module_get_path(gum_process_get_main_module());
}

} // namespace

DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_replace_network_tick(char upload_tick, char download_tick,
                                                              bool isclient) {
#ifndef _WIN32
    (void)upload_tick;
    (void)download_tick;
    (void)isclient;
    return 0;
#else
    auto *ictx = InjectorCtx::instance();
    if (isclient != ictx->DontStarveInjectorIsClient) {
        return 0;
    }
    if (!upload_tick) {
        upload_tick = 10;
    }
    if (!download_tick && !upload_tick) {
        download_tick = 15;
    }
    static struct NetworkTickContext {
        char *upload_address;
        char *uploadtime_address;
        char *download_address;
    } ctx{};
    static auto client_network_tick_addr = [] {
        function_relocation::MemorySignature reset_network_tick_val = {
            "BB 0F 00 00 00 48 83 B9 88 02 00 00 00", 1};
        function_relocation::MemorySignature default_client_network_tick_time = {"44 8D 76 64", 0x3};
        function_relocation::MemorySignature default_client_network_tick_update_fps = {
            "41 BC 0A 00 00 00 85 D2", 0};
        auto mainpath = main_module_path();
        if (reset_network_tick_val.scan(mainpath) && default_client_network_tick_time.scan(mainpath) &&
            default_client_network_tick_update_fps.scan(mainpath)) {
            auto patched_address =
                (std::array<char, 3> *)(default_client_network_tick_update_fps.target_address + 6);
            protect_memory_writer(patched_address, std::array<char, 3>{char(0x90), char(0x90), char(0xEB)});
            auto b1 = (char *)default_client_network_tick_time.target_address;
            ctx.download_address = (char *)reset_network_tick_val.target_address;
            ctx.uploadtime_address = b1;
            ctx.upload_address = (char *)default_client_network_tick_update_fps.target_address + 2;
            return true;
        }
        return false;
    }();
    if (client_network_tick_addr) {
        if (!ictx->DontStarveInjectorIsClient) {
            download_tick = upload_tick;
        }
        upload_tick = std::min<char>(120, upload_tick);
        protect_memory_writer(ctx.upload_address, upload_tick);
        auto tick_time = (char)(int)(1000.0 / upload_tick);
        protect_memory_writer(ctx.uploadtime_address, tick_time);
        download_tick = std::min<char>(120, download_tick);
        protect_memory_writer(ctx.download_address, download_tick);
    }
    return 0;
#endif
}
