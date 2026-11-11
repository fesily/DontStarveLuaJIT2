#include "AnimDrawHook.hpp"
#include "GenerateVBHook.hpp"
#include "SilhouetteBatch.hpp"
#include "SunModel.hpp"

#include "ShadowSignatures.hpp"
#include "core/SignatureResolveApi.hpp"
#include "config/InjectorHostConfig.hpp"
#include "util/frida_gum_interceptor.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>
#include "ShadowLog.hpp"


#include <algorithm>
#include <cstring>

#include <cstdint>

#ifdef _WIN32

namespace ds::shadow {
namespace {

using Dcr_fn = void(__fastcall *)(void *tdc, void *renderer);
using CacheWorld_fn = void(__fastcall *)(void *game, void *cache);

Dcr_fn original_ShadowDCR = nullptr;
CacheWorld_fn original_CacheWorld = nullptr;
bool installed = false;

// Resolved once per process by InstallSilhouetteHooks(). These are consumed
// addresses (they double as vtable identity values), not definitions: the
// patterns, the lowest-hit rule and the rel32 windows live in
// ShadowSignatures.cpp.
uintptr_t g_anim_dcr = 0;
uintptr_t g_shadow_dcr = 0;
uintptr_t g_cache_world = 0;

// Resolve one entry through the shared registry. A miss is reported by the
// manager's audit line; the caller decides whether it is fatal.
uintptr_t ResolveEntry(const char *name, ds::sig::ResolveReport &report) {
    if (!ds::sig::host_resolve(name, &report) || report.target_va == 0) {
        report.target_va = 0;
        return 0;
    }
    return static_cast<uintptr_t>(report.target_va);
}

void RefreshHealthy(void *renderer) {
    if (BindProgramPinned() && (LoadSilShader() || LoadSilFromRenderer(renderer))) {
        SetSilhouetteHealthy(true);
    } else {
        SetSilhouetteHealthy(false);
    }
}

void PreCollectCache(void *cache) {
    static uint32_t npre = 0;
    if (cache == nullptr) {
        return;
    }
    const auto sample = LoadPublished();
    if (!sample.visible || sample.alpha < 1e-3f) {
        return;
    }

    auto *layers = *reinterpret_cast<uint8_t **>(static_cast<uint8_t *>(cache) + 0x450);
    const uint32_t nlayer = *reinterpret_cast<uint32_t *>(static_cast<uint8_t *>(cache) + 0x468);
    if (layers == nullptr || nlayer == 0 || nlayer > 0x1000) {
        return;
    }
    int nodes = 0;
    int ds_n = 0;
    int pack_n = 0;
    for (uint32_t i = 0; i < nlayer; ++i) {
        auto *layer = layers + static_cast<size_t>(i) * 0x30u;
        auto *begin = *reinterpret_cast<uint8_t **>(layer + 0x18);
        auto *end = *reinterpret_cast<uint8_t **>(layer + 0x20);
        if (begin == nullptr || end == nullptr || end < begin) {
            continue;
        }
        const auto bytes = static_cast<size_t>(end - begin);
        if (bytes > 0x100000u || (bytes % sizeof(void *)) != 0) {
            continue;
        }
        for (auto *it = begin; it < end && !SilhouetteBudgetHit(); it += sizeof(void *)) {
            auto *node = *reinterpret_cast<uint8_t **>(it);
            if (!ReadableUserPtr(node, 16)) {
                continue;
            }
            ++nodes;
            auto *nvt = *reinterpret_cast<void ***>(node);
            void *nvt0 = (nvt != nullptr) ? nvt[0] : nullptr;
            if (nvt0 != nullptr && nvt0 == reinterpret_cast<void *>(g_shadow_dcr)) {
                continue;
            }
            auto *inner = *reinterpret_cast<uint8_t **>(node + 8);
            uint8_t *tdc = node;
            if (ReadableUserPtr(inner, 0xC0)) {
                auto *sanim = *reinterpret_cast<void **>(inner + 0xB0);
                auto *sbuild = *reinterpret_cast<void **>(inner + 0xB8);
                if (ReadableUserPtr(sanim) && ReadableUserPtr(sbuild)) {
                    tdc = inner;
                }
            }
            if (!ReadableUserPtr(tdc, 0xC0)) {
                continue;
            }
            auto *sanim = *reinterpret_cast<void **>(tdc + 0xB0);
            auto *sbuild = *reinterpret_cast<void **>(tdc + 0xB8);
            if (!ReadableUserPtr(sanim) || !ReadableUserPtr(sbuild)) {
                continue;
            }
            void *entity = EntityFromTdcViaDsList(tdc);
            void *key = entity != nullptr ? entity : tdc;
            if (IsSilhouetted(key)) {
                continue;
            }
            if (entity != nullptr) {
                ++ds_n;
            }
            if (PackFromTdc(tdc, entity, sample)) {
                MarkSilhouetted(key);
                ++pack_n;
            }
        }
    }
    ++npre;
    if (npre <= 8 || (npre % 60u) == 0) {
        uint32_t pfn = 0, puv = 0, pfr = 0, pel = 0, pad = 0;
        PackFailCounts(&pfn, &puv, &pfr, &pel, &pad);
        SHADOW_TRACE("[render.shadow] precollect n={} layers={} nodes={} ds={} pack={} marked={} "
                     "verts={} fail fn={} uv={} frame={} elems={} empty={}",
                     npre, nlayer, nodes, ds_n, pack_n, SilhouettedCount(), BatchVertCount(), pfn,
                     puv, pfr, pel, pad);
    }

}

void __fastcall hooked_ShadowDCR(void *tdc_shadow, void *renderer) {
    if (original_ShadowDCR != nullptr) {
        original_ShadowDCR(tdc_shadow, renderer);
    }
    if (!IsSilhouetteEnabled()) {
        return;
    }
    if (!IsSilhouetteHealthy()) {
        RefreshHealthy(renderer);
    }
    if (IsSilhouetteHealthy() && BatchVertCount() > 0) {
        FlushSilhouettes(renderer);
    }
    ClearSilhouetted();
}

void __fastcall hooked_CacheWorld(void *game, void *cache) {
    BeginSilhouetteFrame();
    NoteGameAnimManager(game);
    if (IsSilhouetteEnabled()) {
        PreCollectCache(cache);
    }
    if (original_CacheWorld != nullptr) {
        original_CacheWorld(game, cache);
    }
}

void RevertAll(GumInterceptor *interceptor) {
    if (interceptor == nullptr) {
        return;
    }
    if (original_ShadowDCR != nullptr && g_shadow_dcr != 0) {
        gum_interceptor_revert(interceptor, reinterpret_cast<void *>(g_shadow_dcr));
        original_ShadowDCR = nullptr;
    }
    if (original_CacheWorld != nullptr && g_cache_world != 0) {
        gum_interceptor_revert(interceptor, reinterpret_cast<void *>(g_cache_world));
        original_CacheWorld = nullptr;
    }
}


} // namespace

bool InstallSilhouetteHooks() {
    if (installed) {
        if (!IsHookInstalled()) {
            SetSilhouetteHealthy(false);
            return false;
        }
        return IsSilhouetteHealthy();
    }
    if (!IsHookInstalled()) {
        if (!InstallGenerateVBHook() || !IsHookInstalled()) {
            spdlog::error("[render.shadow] silhouette: GenerateVB hook required");
            SetSilhouetteHealthy(false);
            return false;
        }
    }
    auto *ictx = InjectorCtx::instance();
    if (ictx == nullptr || !ictx->DontStarveInjectorIsClient) {
        SHADOW_TRACE("[render.shadow] skip silhouette hooks: not client");
        SetSilhouetteHealthy(false);
        return false;
    }
    const auto *mainPath = gum_module_get_path(gum_process_get_main_module());
    if (mainPath == nullptr) {
        spdlog::error("[render.shadow] silhouette: no main module path");
        SetSilhouetteHealthy(false);
        return false;
    }
    if (std::strstr(mainPath, "dedicated") != nullptr ||
        std::strstr(mainPath, "nullrenderer") != nullptr) {
        SHADOW_TRACE("[render.shadow] skip silhouette hooks: dedicated/nullrenderer");
        SetSilhouetteHealthy(false);
        return false;
    }
    const auto gvb = GetGenerateVBAddress();
    if (gvb == 0) {
        spdlog::error("[render.shadow] silhouette: GenerateVB address unavailable");
        SetSilhouetteHealthy(false);
        return false;
    }
    ds::sig::ResolveReport anim_report{};
    ds::sig::ResolveReport shadow_report{};
    ds::sig::ResolveReport cache_report{};
    ds::sig::ResolveReport getframe_report{};
    ds::sig::ResolveReport hwbind_report{};
    ds::sig::ResolveReport animdraw_report{};
    const uintptr_t anim = ResolveEntry("render.shadow.anim_dcr", anim_report);
    const uintptr_t shadow = ResolveEntry("render.shadow.shadow_dcr", shadow_report);
    const uintptr_t cache = ResolveEntry("render.shadow.cache_world", cache_report);
    const uintptr_t getframe = ResolveEntry("render.shadow.get_anim_frame", getframe_report);
    const uintptr_t hwbind = ResolveEntry("render.shadow.hw_effect_bind", hwbind_report);
    const uintptr_t animdraw = ResolveEntry("render.shadow.anim_draw", animdraw_report);
    SHADOW_TRACE("[render.shadow] resolve gvb={:#x} anim={:#x} shadow={:#x} cache={:#x} "
                 "getframe={:#x} hwbind={:#x} animdraw={:#x}",
                 gvb, anim, shadow, cache, getframe, hwbind, animdraw);

    if (shadow == 0 || cache == 0 || getframe == 0) {
        spdlog::error("[render.shadow] silhouette signature miss shadow={:#x} cache={:#x} "
                      "getframe={:#x}",
                      shadow, cache, getframe);
        SetSilhouetteHealthy(false);
        return false;
    }
    g_shadow_dcr = shadow;
    g_cache_world = cache;
    if (anim != 0) {
        g_anim_dcr = anim;
    }
    if (!BindSilhouetteHelpers(anim, shadow, gvb)) {
        spdlog::error("[render.shadow] silhouette helper Rel32 failed");
        SetSilhouetteHealthy(false);
        return false;
    }

    BindGetAnimFrame(getframe);
    BindHwEffectBind(hwbind);
    BindAnimDraw(animdraw);
    if (animdraw == 0) {
        spdlog::error("[render.shadow] AnimDraw pin miss — B unhealthy");
        SetSilhouetteHealthy(false);
    }
    if (!BindProgramPinned()) {
        spdlog::error("[render.shadow] BindProgram pin miss — B unhealthy");
        SetSilhouetteHealthy(false);
    }

    auto *interceptor = InjectorCtx::instance()->GetGumInterceptor();
    if (interceptor == nullptr) {
        spdlog::error("[render.shadow] silhouette: GumInterceptor unavailable");
        SetSilhouetteHealthy(false);
        return false;
    }

    const auto rs = ds::gum::replace(interceptor,
                                     reinterpret_cast<void *>(g_shadow_dcr),
                                     reinterpret_cast<void *>(&hooked_ShadowDCR),
                                     reinterpret_cast<void **>(&original_ShadowDCR));
    const auto rc = ds::gum::replace(interceptor,
                                     reinterpret_cast<void *>(g_cache_world),
                                     reinterpret_cast<void *>(&hooked_CacheWorld),
                                     reinterpret_cast<void **>(&original_CacheWorld));
    if (rs != GUM_REPLACE_OK || rc != GUM_REPLACE_OK) {
        spdlog::error("[render.shadow] silhouette gum replace failed shadow={} cache={}",
                      static_cast<int>(rs), static_cast<int>(rc));
        RevertAll(interceptor);
        SetSilhouetteHealthy(false);
        return false;
    }

    installed = true;
    if (!IsHookInstalled()) {
        RevertAll(interceptor);
        installed = false;
        SetSilhouetteHealthy(false);
        return false;
    }
    if (BindProgramPinned() && LoadSilShader()) {
        SetSilhouetteHealthy(true);
    } else {
        SetSilhouetteHealthy(false);
    }
    SHADOW_TRACE("[render.shadow] silhouette hooks @ shadow={:#x} cache={:#x} getframe={:#x} "
                 "anim={:#x} gvb={:#x} hwbind={:#x} sil_fx={:#x} sil_vd={:#x} healthy={}",
                 shadow, cache, getframe, anim, gvb, hwbind, SilEffectHandle(),
                 SilVertDescHandle(), IsSilhouetteHealthy() ? 1 : 0);
    return true;
}

} // namespace ds::shadow

#else

namespace ds::shadow {

bool InstallSilhouetteHooks() {
    SetSilhouetteHealthy(false);
    return false;
}

} // namespace ds::shadow

#endif
