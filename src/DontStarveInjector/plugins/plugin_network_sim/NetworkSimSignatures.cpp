#include "NetworkSimSignatures.hpp"

#if defined(DS_SIG_HAVE_NETWORK_SIM)
namespace ds::network_sim {
namespace {

using namespace ds::sig;

constexpr uint32_t kWin = kPlatformWindowsX64;

EntryDef g_entries[] = {
        {
                .owner = "network.sim",
                .name = "network.sim.send_bitstream",
                .description = "BitStream::SendBitStream prologue with stack cookie and arg load",
                .patterns = {"40 53 55 56 57 41 54 41 55 48 83 EC 68 "
                             "48 8B 05 ?? ?? ?? ?? "
                             "48 33 C4 "
                             "48 89 44 24 58 "
                             "41 8B 39 48"},
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
        {
                .owner = "network.sim",
                .name = "network.sim.reliability_dtor",
                .description = "ReliabilityLayer::~ReliabilityLayer prologue (double vtable store)",
                .patterns = {"48 89 5C 24 10 "
                             "48 89 74 24 18 "
                             "57 "
                             "48 83 EC 20 "
                             "48 8D 05 ?? ?? ?? ?? "
                             "41 B9 03 00 00 00 "
                             "45 33 C0 "
                             "48 89 01 "
                             "48 8D 05 ?? ?? ?? ?? "
                             "33 D2 "
                             "48 89 41 08 "
                             "48"},
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
        .owner = "network.sim",
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

} // namespace ds::network_sim
#endif // DS_SIG_HAVE_NETWORK_SIM
