#include "NetworkRpcSignatures.hpp"

#if defined(DS_SIG_HAVE_NETWORK_RPC)
namespace ds::network_rpc {
namespace {

using namespace ds::sig;

constexpr uint32_t kWin = kPlatformWindowsX64;

EntryDef g_entries[] = {
        // 2026-11-06 build (TS 0x6aed2496) added a second `sub rsp,330h; mov rax,[rip]`
        // function (rva 0x1bde27), which broke the old 11-byte literal's uniqueness. Extend
        // through the stack-cookie store so only the real RPC4::Signal matches (client rva
        // 0x3b7b67, -0x7 -> entry 0x3b7b60; server: single hit 0x351e27 -> 0x351e20).
        {
                .owner = "network.rpc",
                .name = "network.rpc.rpc4_signal",
                .description = "RakNet RPC4::Signal prologue with stack-cookie store",
                .patterns = {"48 81 EC 30 03 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 48 89 84 24 20 03 00 00 "
                             "48 8B 9C 24 90 03 00 00"},
                .pattern_offset = -0x7,
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
        // pro->reliability = PacketReliability::RELIABLE_ORDERED (mov dword [rdi+134], 3)
        {
                .owner = "network.rpc",
                .name = "network.rpc.component_serialize",
                .description = "NetworkComponent::Serialize reliability store (mov [rdi+134h], 3)",
                .patterns = {"C7 87 34 01 00 00 03 00 00 00"},
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
        // check channel size = 0x80/4 = 32 ordered streams.
        // 2026-11-06 build: ReliabilityLayer's ordered-stream arrays grew, so the first
        // 0x80-byte memset moved from +0x1268 to +0x12F0 (later ones: +0x1110/+0x1370/+0x16F0).
        // Anchored on the +0x12F0 memset — still exactly one hit in client and server.
        {
                .owner = "network.rpc",
                .name = "network.rpc.ordered_streams",
                .description = "ReliabilityLayer::InitializeVariables ordered-stream memset (128 bytes @ +12F0h)",
                .patterns = {"48 8D 8B F0 12 00 00 33 D2 41 B8 80"},
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
        // lea rax, NetworkComponentReplica3_vtb — the constructor is where the vtable
        // identity value gets published, which is what the extension keys on.
        {
                .owner = "network.rpc",
                .name = "network.rpc.component_ctor",
                .description = "NetworkComponentReplica3 constructor (vtable store after lea)",
                .patterns = {"48 8D 8B E8 01 00 00 48 89 43 20"},
                .pattern_offset = -7,
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
        .owner = "network.rpc",
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

} // namespace ds::network_rpc
#endif // DS_SIG_HAVE_NETWORK_RPC
