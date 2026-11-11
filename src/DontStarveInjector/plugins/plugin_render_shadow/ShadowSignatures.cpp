#include "ShadowSignatures.hpp"

#include <cstdio>
#include <cstring>

#if defined(DS_SIG_HAVE_RENDER_SHADOW)
namespace ds::shadow {
namespace {

using namespace ds::sig;

constexpr uint32_t kWin = kPlatformWindowsX64;

// Helper call sites inside GenerateVB, all `E8 rel32`: get_vert_desc, get_cam,
// get_vert_desc(again), populate_quad, create_vb, free_verts. The consumer reads
// the displacement at these fixed offsets from the resolved base.
constexpr intptr_t kGenerateVbCallSites[] = {0x32, 0xAB, 0x157, 0x1A9, 0x1B9, 0x57};

bool verify_generate_vb(const EntryDef &, const ContextView &ctx, uintptr_t target, uintptr_t, char *detail,
                        size_t detail_cap) {
    if (target < ctx.module_base || (ctx.module_size != 0 && target - ctx.module_base + 0x1C0 >= ctx.module_size)) {
        std::snprintf(detail, detail_cap, "GenerateVB base is outside the module");
        return false;
    }
    const auto *base = reinterpret_cast<const uint8_t *>(target);
    for (const auto offset : kGenerateVbCallSites) {
        if (base[offset] != 0xE8) {
            std::snprintf(detail, detail_cap, "helper call site +0x%llx is not a rel32 call",
                          static_cast<unsigned long long>(offset));
            return false;
        }
    }
    return true;
}

// The animation-draw node addresses double as vtable identity values, so they must
// land inside the module the scan covered.
bool verify_in_text(const EntryDef &, const ContextView &ctx, uintptr_t target, uintptr_t, char *detail,
                    size_t detail_cap) {
    if (target < ctx.module_base || (ctx.module_size != 0 && target - ctx.module_base >= ctx.module_size)) {
        std::snprintf(detail, detail_cap, "address is outside the module");
        return false;
    }
    return true;
}

EntryDef g_entries[] = {
        // 2026-11-06 build (TS 0x6aed2496): the renderer member moved 0x920 -> 0x928.
        {
                .owner = "render.shadow",
                .name = "render.shadow.anim_dcr",
                .description = "Animation draw collection routine (lowest hit wins)",
                .patterns = {"40 53 57 41 56 48 81 EC 90 04 00 00 48 8B D9 48 8B 8A 28 09 00 00 48 8B FA 48 8B 49 28"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
        // 2026-11-06 build: [rdx+0x930] -> [rdx+0x938] and the short-jump displacement 0xDD -> 0xDA.
        {
                .owner = "render.shadow",
                .name = "render.shadow.shadow_dcr",
                .description = "Shadow draw collection routine (lowest hit wins)",
                .patterns = {"48 89 74 24 10 57 48 83 EC 20 83 BA 38 09 00 00 02 48 8B FA 48 8B F1 0F 85 DA 00 00 00"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
        {
                .owner = "render.shadow",
                .name = "render.shadow.cache_world",
                .description = "World cache pre-collect (lowest hit wins)",
                .patterns = {"48 89 54 24 10 56 41 56 48 81 EC 58 02 00 00 48 8B F1 48 8B 89 70 01 00 00"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
        // Used as a vtable identity value by the anim-draw probe.
        {
                .owner = "render.shadow",
                .name = "render.shadow.get_anim_frame",
                .description = "GetAnimFrame (lowest hit wins; address doubles as vtable identity)",
                .patterns = {"48 83 EC 28 4C 8B C9 E8 ?? ?? ?? ?? 83 F8 FF 74 13 8B C0 48 8D 14 80"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
        // HWEffect::Bind — unique prologue; updates src_data, SetEffect does not.
        {
                .owner = "render.shadow",
                .name = "render.shadow.hw_effect_bind",
                .description = "HWEffect::Bind (lowest hit wins)",
                .patterns = {"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 41 8B 40 1C"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
        {
                .owner = "render.shadow",
                .name = "render.shadow.anim_draw",
                .description = "AnimDraw entry (lowest hit wins)",
                .patterns = {"48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B 01 41"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
        {
                .owner = "render.shadow",
                .name = "render.shadow.generate_vb",
                .description = "GenerateVB base plus the rel32 helper call sites the consumer walks",
                .patterns = {"48 89 5C 24 18 48 89 6C 24 20 56 57 41 54 48 83 EC 50 48 8B 41 20 48 8B FA 48 8B F1 "
                             "8B 90 D4 00 00 00"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_generate_vb,
        },
        // ResourceManager::Load (= LoadShader). The bare prologue is not unique across
        // builds — include the stack-cookie frame of the 0x100-byte path buffer.
        {
                .owner = "render.shadow",
                .name = "render.shadow.load_shader",
                .description = "ResourceManager::Load (silhouette shader load, lowest hit wins)",
                .patterns = {"40 53 55 56 57 41 54 41 55 41 56 48 81 EC 00 01 00 00 48 8B 05 ?? ?? ?? ?? 48 33 C4 "
                             "48 89 84 24 D0 00 00 00 48 8B F9"},
                .pattern_offset = 0,
                .platform_mask = kWin,
                .prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ,
                .hits_policy = static_cast<int32_t>(HitsPolicy::Lowest),
                .resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset),
                .definition_revision = 1,
                .client_only = 1,
                .server_only = 0,
                .audit_log = 0,
                .reserved = 0,
                .verify = &verify_in_text,
        },
};

const ProviderDesc g_desc{
        .owner = "render.shadow",
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

} // namespace ds::shadow
#endif // DS_SIG_HAVE_RENDER_SHADOW
