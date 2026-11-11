#include "ProfilerSignatures.hpp"

#if defined(DS_SIG_HAVE_DEBUG_PROFILER)
namespace ds::debug_profiler {
namespace {

using namespace ds::sig;

#if defined(DS_SIG_TARGET_WINDOWS_X64)
constexpr uint32_t kWin = kPlatformWindowsX64;
#else
constexpr uint32_t kLinux = kPlatformLinuxX64;
#endif

// Only the variants of the target this build compiles for are emitted.
EntryDef g_entries[] = {
#if defined(DS_SIG_TARGET_WINDOWS_X64)
        // FrameProfiler::Push. Windows pins a body offset inside the stock body.
        {
                .owner = "debug.profiler",
                .name = "debug.profiler.push",
                .description = "FrameProfiler::Push (win64 body, -0x175 prologue)",
                .patterns = {"44 8B 9B 88 02 00 00"},
                .pattern_offset = -0x175,
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
        // FrameProfiler::Pop. Windows pins the body prologue.
        {
                .owner = "debug.profiler",
                .name = "debug.profiler.pop",
                .description = "FrameProfiler::Pop (win64 body, -0x7D prologue)",
                .patterns = {"81 7F 1C 00 3C 00 00"},
                .pattern_offset = -0x7D,
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
#else // linux-x64
        // Linux resolves the exact FDE entry because GCC 9 splits Push into an
        // enabled-check wrapper plus a .part.0 body.
        {
                .owner = "debug.profiler",
                .name = "debug.profiler.push",
                .description = "FrameProfiler::Push (linux-x64, FDE entry)",
                .patterns = {"F3 0F 1E FA 0F B6 47 20 84 C0 74 ?? E9"},
                .pattern_offset = 0,
                .platform_mask = kLinux,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::FdeEntry),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        // Constant-propagated singleton wrapper that also calls the Push body.
        {
                .owner = "debug.profiler",
                .name = "debug.profiler.push_singleton",
                .description = "FrameProfiler::Push singleton wrapper (linux-x64, FDE entry)",
                .patterns = {"F3 0F 1E FA 48 8B 3D ?? ?? ?? ?? 0F B6 47 20 84 C0 74 ?? E9"},
                .pattern_offset = 0,
                .platform_mask = kLinux,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::FdeEntry),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
        {
                .owner = "debug.profiler",
                .name = "debug.profiler.pop",
                .description = "FrameProfiler::Pop (linux-x64, FDE entry)",
                .patterns = {"64 48 8B 1C 25 F8 FF FF FF"},
                .pattern_offset = 0,
                .platform_mask = kLinux,
                .prot_flag = 0,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Unique),
                .resolve_kind = static_cast<int32_t>(ResolveKind::FdeEntry),
                .definition_revision = 1,
                .client_only = 0,
                .server_only = 0,
                .audit_log = 1,
                .reserved = 0,
                .verify = nullptr,
        },
#endif
};

const ProviderDesc g_desc{
        .owner = "debug.profiler",
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

} // namespace ds::debug_profiler
#endif // DS_SIG_HAVE_DEBUG_PROFILER
