#include "VbpoolSignatures.hpp"

#if defined(DS_SIG_HAVE_RENDER_VBPOOL)
namespace ds::render_vbpool {
namespace {

using namespace ds::sig;

constexpr uint32_t kWin = kPlatformWindowsX64;

EntryDef g_entries[] = {
        // HWBuffer::Init(this, const void* data) — unique prologue of the win64 body.
        {
                .owner = "render.vbpool",
                .name = "render.vbpool.hwbuffer_init",
                .description = "HWBuffer::Init (unique win64 prologue)",
                .patterns = {"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 48 83 EC 20 "
                             "4C 8B E2 48 8D 51 10 48 8B E9 B9 01 00 00 00"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        // HWBuffer::~HWBuffer() non-deleting dtor: zeroes glBufferID before calling the
        // original, so glDeleteBuffers(1, &0) becomes a no-op in OpenGL.
        {
                .owner = "render.vbpool",
                .name = "render.vbpool.hwbuffer_dtor",
                .description = "HWBuffer::~HWBuffer (non-deleting dtor, vtable store then glBufferID)",
                .patterns = {"40 53 48 83 EC 20 48 8D 05 ?? ?? ?? ?? 48 8D 51 10 48 8B D9 48 89 01 B9 01 00 00 00"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        // Batcher::Flush(this) — prologue plus the 1/3 stride magic constant.
        {
                .owner = "render.vbpool",
                .name = "render.vbpool.batcher_flush",
                .description = "Batcher::Flush (prologue plus 0xAAAA…AA2A stride constant)",
                .patterns = {"4C 8B DC 49 89 6B 18 57 48 83 EC 70 48 8B 51 78 48 BD AB AA AA AA AA AA AA 2A"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
};

const ProviderDesc g_desc{
        .owner = "render.vbpool",
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

} // namespace ds::render_vbpool
#endif // DS_SIG_HAVE_RENDER_VBPOOL
