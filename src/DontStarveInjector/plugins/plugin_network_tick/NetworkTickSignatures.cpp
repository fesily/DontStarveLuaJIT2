#include "NetworkTickSignatures.hpp"

#if defined(DS_SIG_HAVE_NETWORK_TICK)
namespace ds::network_tick {
namespace {

using namespace ds::sig;

constexpr uint32_t kWin = kPlatformWindowsX64;

EntryDef g_entries[] = {
        {
                .owner = "network.tick",
                .name = "network.tick.reset_value",
                .description = "ClientNetworkTick reset value byte (mov ebx, 0F)",
                .patterns = {"BB 0F 00 00 00 48 83 B9 88 02 00 00 00"},
                .pattern_offset = 1,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "network.tick",
                .name = "network.tick.client_tick_time",
                .description = "Client tick-time byte (lea rsi, [rsi+64h])",
                .patterns = {"44 8D 76 64"},
                .pattern_offset = 3,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "network.tick",
                .name = "network.tick.update_fps",
                .description = "Client update-fps immediate (mov r12d, 0Ah) plus its 3-byte patch window",
                .patterns = {"41 BC 0A 00 00 00 85 D2"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
};

const ProviderDesc g_desc{
        .owner = "network.tick",
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

} // namespace ds::network_tick
#endif // DS_SIG_HAVE_NETWORK_TICK
