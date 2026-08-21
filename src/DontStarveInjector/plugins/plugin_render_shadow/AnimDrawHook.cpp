#include "AnimDrawHook.hpp"
#include "GenerateVBHook.hpp"
#include "SilhouetteBatch.hpp"
#include "SunModel.hpp"

#include "MemorySignature.hpp"
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

function_relocation::MemorySignature AnimDCR_sig{
    "40 53 57 41 56 48 81 EC 90 04 00 00 48 8B D9 48 8B 8A 20 09 00 00 48 8B FA 48 8B 49 28", 0};

function_relocation::MemorySignature ShadowDCR_sig{
    "48 89 74 24 10 57 48 83 EC 20 83 BA 30 09 00 00 02 48 8B FA 48 8B F1 0F 85 DD 00 00 00", 0};

function_relocation::MemorySignature CacheWorld_sig{
    "48 89 54 24 10 56 41 56 48 81 EC 58 02 00 00 48 8B F1 48 8B 89 70 01 00 00", 0};

function_relocation::MemorySignature GetAnimFrame_sig{
    "48 83 EC 28 4C 8B C9 E8 ?? ?? ?? ?? 83 F8 FF 74 13 8B C0 48 8D 14 80", 0};

// HWEffect::Bind — unique prologue @ 1403e92f0. Updates src_data; SetEffect does not.
function_relocation::MemorySignature HwEffectBind_sig{
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 41 8B 40 1C", 0};

function_relocation::MemorySignature AnimDraw_sig{
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 20 48 8B 01 41", 0};


uintptr_t ScanLowest(function_relocation::MemorySignature &sig, const char *path) {
    sig.only_one = false;
    sig.log = false;
    sig.prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ;
    sig.target_address = 0;
    sig.targets.clear();
    sig.scan(path);
    if (sig.targets.empty()) {
        return 0;
    }
    return *std::min_element(sig.targets.begin(), sig.targets.end());
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
            if (nvt0 != nullptr && nvt0 == reinterpret_cast<void *>(ShadowDCR_sig.target_address)) {
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
    if (original_ShadowDCR != nullptr && ShadowDCR_sig.target_address != 0) {
        gum_interceptor_revert(interceptor,
                               reinterpret_cast<void *>(ShadowDCR_sig.target_address));
        original_ShadowDCR = nullptr;
    }
    if (original_CacheWorld != nullptr && CacheWorld_sig.target_address != 0) {
        gum_interceptor_revert(interceptor,
                               reinterpret_cast<void *>(CacheWorld_sig.target_address));
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
    const uintptr_t anim = ScanLowest(AnimDCR_sig, mainPath);
    const uintptr_t shadow = ScanLowest(ShadowDCR_sig, mainPath);
    const uintptr_t cache = ScanLowest(CacheWorld_sig, mainPath);
    const uintptr_t getframe = ScanLowest(GetAnimFrame_sig, mainPath);
    const uintptr_t hwbind = ScanLowest(HwEffectBind_sig, mainPath);
    const uintptr_t animdraw = ScanLowest(AnimDraw_sig, mainPath);
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
    ShadowDCR_sig.target_address = shadow;
    CacheWorld_sig.target_address = cache;
    if (anim != 0) {
        AnimDCR_sig.target_address = anim;
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
                                     reinterpret_cast<void *>(ShadowDCR_sig.target_address),
                                     reinterpret_cast<void *>(&hooked_ShadowDCR),
                                     reinterpret_cast<void **>(&original_ShadowDCR));
    const auto rc = ds::gum::replace(interceptor,
                                     reinterpret_cast<void *>(CacheWorld_sig.target_address),
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
