#include "NetStatsSignatures.hpp"

#include "ClientPingDecode.hpp"

#include <cstdio>

#if defined(DS_SIG_HAVE_NETWORK_STATS)
namespace ds::net_stats {
namespace {

using namespace ds::sig;

#if defined(DS_SIG_TARGET_WINDOWS_X64)
constexpr uint32_t kWin = kPlatformWindowsX64;
#else
constexpr uint32_t kLinux = kPlatformLinuxX64;
#endif

// cNetworkClientObject2::UpdateNetStats. Verified shapes (2026-10, both binaries
// scanned; total hits must be exactly 1):
//   Windows x64  dontstarve_steam_x64.exe and
//                dontstarve_dedicated_server_nullrenderer_x64.exe
//                — the same literal covers both Windows binaries.
//   Linux x64    dontstarve_dedicated_server_nullrenderer_x64.
bool verify_net_stats(const EntryDef &, const ContextView &, uintptr_t target, uintptr_t, char *detail,
                      size_t detail_cap) {
    const auto layout = decode_net_stats(target);
    if (!layout) {
        std::snprintf(detail, detail_cap, "%s", layout.error().c_str());
        return false;
    }
    return true;
}

EntryDef g_entries[] = {
#if defined(DS_SIG_TARGET_WINDOWS_X64)
        {
                .owner = "network.stats",
                .name = "network.stats.update_net_stats",
                .description = "cNetworkClientObject2::UpdateNetStats anchor (win64)",
                // mov r11,rsp; push rbx; push rsi; sub rsp,imm32; mov rax,[rip+d];
                // mov rbx,rcx; mov rsi,[rax+2B0h]; test rsi,rsi
                .patterns = {"4C 8B DC 53 56 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B D9 48 8B B0 B0 "
                             "02 00 00 48 85 F6"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 0, // the consumer reports hits itself
                .reserved = 0,
                .verify = &verify_net_stats,
        },
#else // linux-x64
        {
                .owner = "network.stats",
                .name = "network.stats.update_net_stats",
                .description = "cNetworkClientObject2::UpdateNetStats anchor (linux-x64)",
                // push r14; push r13; push r12; push rbp; push rbx; sub rsp,140h;
                // mov rax,fs:[28h]; mov [rsp+138h],rax; xor eax,eax; mov rax,[rip+d];
                // mov rbp,[rax+1A0h]; test rbp,rbp
                .patterns = {"41 56 41 55 41 54 55 53 48 81 EC 40 01 00 00 64 48 8B 04 25 28 00 00 00 48 89 "
                             "84 24 38 01 00 00 31 C0 48 8B 05 ?? ?? ?? ?? 48 8B A8 A0 01 00 00 48 85 ED"},
                .pattern_offset = 0,
                .platform_mask = kLinux,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_net_stats,
        },
#endif
};

const ProviderDesc g_desc{
        .owner = "network.stats",
        .provider_version = "1",
        .entries = g_entries,
        .entry_count = sizeof(g_entries) / sizeof(g_entries[0]),
        .repair = nullptr,
        .prepare = nullptr,
};

} // namespace

const ds::sig::ProviderDesc &signature_provider() {
    return g_desc;
}

} // namespace ds::net_stats
#endif // DS_SIG_HAVE_NETWORK_STATS
