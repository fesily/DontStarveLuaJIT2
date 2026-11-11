// plugin_network_tick — DS_LUAJIT_replace_network_tick
#include "config/InjectorHostConfig.hpp"
#include "NetworkTickSignatures.hpp"
#include "core/SignatureResolveApi.hpp"
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
        // Definitions (and their internal-byte offsets) live in
        // NetworkTickSignatures.cpp; all three must resolve before anything is
        // patched, so one stale literal leaves the tick untouched.
        ds::sig::ResolveReport reset_value{};
        ds::sig::ResolveReport tick_time{};
        ds::sig::ResolveReport update_fps{};
        const bool have_reset = ds::sig::host_resolve("network.tick.reset_value", &reset_value);
        const bool have_time = ds::sig::host_resolve("network.tick.client_tick_time", &tick_time);
        const bool have_fps = ds::sig::host_resolve("network.tick.update_fps", &update_fps);
        if (!have_reset || !have_time || !have_fps) {
            return false;
        }
        auto patched_address = (std::array<char, 3> *)(update_fps.target_va + 6);
        protect_memory_writer(patched_address, std::array<char, 3>{char(0x90), char(0x90), char(0xEB)});
        auto b1 = (char *)tick_time.target_va;
        ctx.download_address = (char *)reset_value.target_va;
        ctx.uploadtime_address = b1;
        ctx.upload_address = (char *)update_fps.target_va + 2;
        return true;
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
