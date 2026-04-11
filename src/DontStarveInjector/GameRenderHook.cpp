#include "GameRenderHook.hpp"
#include "ctx.hpp"

#include "config.hpp"
#include "MemorySignature.hpp"
#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <cstdint>
#include <vector>
#include <unordered_map>
#include <egl/egl.h>
#include <GLES2/gl2.h>

#ifdef _WIN32
#include <Windows.h>
constexpr unsigned int GL_ARRAY_BUFFER_CONST = 0x8892;
#endif

// Engine type reconstructions from Ghidra decompilation of dontstarve_steam macOS binary.
// Binary: dontstarve_steam_12527201, x86_64, source: renderlib/OpenGL/HWBuffer.cpp

enum class eUsageType : uint32_t {
    STATIC_DRAW  = 9,    // GL_STATIC_DRAW  0x88E4
    STREAM_DRAW  = 10,   // GL_STREAM_DRAW  0x88E0
    STATIC_COPY  = 0xC,  // GL_STATIC_COPY  0x88E8
    STATIC_READ  = 0x11, // GL_STATIC_READ  0x88E5
    STREAM_READ  = 0x12, // GL_STREAM_READ  0x88E1
    STREAM_COPY  = 0x14, // GL_STREAM_COPY  0x88E9
    DYNAMIC_READ = 0x21, // GL_DYNAMIC_READ 0x88E6
    DYNAMIC_DRAW = 0x22, // GL_DYNAMIC_DRAW 0x88E2
    DYNAMIC_COPY = 0x24, // GL_DYNAMIC_COPY 0x88EA
};

// HWBuffer binary layout from Ghidra (macOS x64):
//   +0x00: vtable*       +0x08: stride (uint32)
//   +0x0C: count (uint32) +0x10: glBufferID (uint32)
//   +0x14: usageType (eUsageType)
struct HWBuffer {
    void*       vtable;
    uint32_t    stride;
    uint32_t    count;
    uint32_t    glBufferID;
    eUsageType  usageType;
};
static_assert(offsetof(HWBuffer, stride)     == 0x08);
static_assert(offsetof(HWBuffer, count)      == 0x0C);
static_assert(offsetof(HWBuffer, glBufferID) == 0x10);
static_assert(offsetof(HWBuffer, usageType)  == 0x14);

// Renderer::CreateVB(this, eUsageType, uint32_t stride, uint32_t count, void* data, bool shadow)
using CreateVB_t = void* (*)(void* renderer, eUsageType usage, uint32_t stride, uint32_t count, const void* data, bool shadow);
// cResourceManager<VertexBuffer>::Release(this, uint handle)
// macOS: 0x10013b1b0 | Windows: FUN_140018a30
using ReleaseVB_t = void (*)(void* resourceMgr, uint32_t handle);
// Batcher::Flush(this)
using BatcherFlush_t = void (*)(void* batcher);
// Renderer::Draw(this, Matrix4& mat, uint vertexCount, Primitive::Type primType)
// Windows has 3 HW-level variants: Draw(4p), DrawCount(5p), DrawSimple(3p)
using RendererDraw_t = void (*)(void* renderer, void* matrix, uint32_t vertexCount, uint32_t primType);

// cResourceManager<VB>::GetResource(this, uint handle) → HWBuffer*
// NOT hooked — called from our hooks to resolve handle→object
// Windows: FUN_1403dc420
using GetResource_t = void* (*)(void* resourceMgr, uint32_t handle);

// IsRenderThread() — returns 1 if current thread is the render thread
// Windows: FUN_140002160
using IsRenderThread_t = int (*)();


// Signature definitions — fill per platform with byte patterns from IDA/Ghidra.
// Ghidra macOS addresses provided as reference comments.
namespace render_signatures {

inline function_relocation::MemorySignature CreateVB_sig{      // Ghidra macOS: 0x1001f3e0e, Windows: 0x1403e2d10
#ifdef _WIN32
    "4C 89 6C 24 58 4C 8B E9 B9 20 00 00 00", -0xB
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

inline function_relocation::MemorySignature ReleaseVB_sig{     // cResourceManager<VB>::Release — macOS: 0x10013b1b0, Windows: 0x140018a30
#ifdef _WIN32
    "83 FA FF 0F 84 22 01 00 00", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

inline function_relocation::MemorySignature BatcherFlush_sig{  // macOS: 0x100167c6c, Windows: 0x140036360
#ifdef _WIN32
    "4C 8B DC 49 89 6B 18 57 48 83 EC 70 48 8B 51 78 48 BD AB AA AA AA AA AA AA 2A", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

inline function_relocation::MemorySignature RendererDraw_sig{  // macOS: 0x1001ead48, Windows: 0x1403dc610
#ifdef _WIN32
    "48 8B 01 49 63 F1 41 8B E8 48 8B DA 48 8B F9", -0x14
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

inline function_relocation::MemorySignature GetResource_sig{   // cResourceManager::GetResource — Windows: 0x1403dc420
#ifdef _WIN32
    "48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20 33 DB 8B FA 48 8B F1 83 FA FF", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

inline function_relocation::MemorySignature IsRenderThread_sig{ // Windows: 0x140002160
#ifdef _WIN32
    "48 83 EC 28 80 3D ?? ?? ?? ?? 00 74 20 48 89 5C 24 20 8B 1D ?? ?? ?? ?? E8 ?? ?? ?? ?? 3B C3", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

} // namespace render_signatures

// Phase 1: Vertex Buffer Pool
// Eliminates per-frame glGenBuffers/glDeleteBuffers by pooling VB objects
// keyed by (stride, roundUpPow2(count)).

struct VBPoolKey {
    uint32_t stride;
    uint32_t capacityBucket;

    bool operator==(const VBPoolKey& o) const {
        return stride == o.stride && capacityBucket == o.capacityBucket;
    }
};

struct VBPoolKeyHash {
    size_t operator()(const VBPoolKey& k) const {
        return std::hash<uint64_t>{}((uint64_t(k.stride) << 32) | k.capacityBucket);
    }
};

class VertexBufferPool {
public:
    static constexpr size_t MAX_POOL_SIZE_PER_BUCKET = 32;
    static constexpr size_t MAX_TOTAL_POOLED = 256;

    void* acquire(uint32_t stride, uint32_t count) {
        auto key = makeKey(stride, count);
        auto it = pool_.find(key);
        if (it != pool_.end() && !it->second.empty()) {
            auto handle = it->second.back();
            it->second.pop_back();
            totalPooled_--;
            stats_.hits++;
            return reinterpret_cast<void*>(static_cast<uintptr_t>(handle));
        }
        stats_.misses++;
        return nullptr;
    }

    bool release(uint32_t handle, uint32_t stride, uint32_t count) {
        if (totalPooled_ >= MAX_TOTAL_POOLED) {
            stats_.evictions++;
            return false;
        }
        auto key = makeKey(stride, count);
        auto& bucket = pool_[key];
        if (bucket.size() >= MAX_POOL_SIZE_PER_BUCKET) {
            stats_.evictions++;
            return false;
        }
        bucket.push_back(handle);
        totalPooled_++;
        return true;
    }

    template<typename ReleaseFn>
    void drainAll(void* resourceMgr, ReleaseFn originalRelease) {
        for (auto& [key, bucket] : pool_) {
            for (uint32_t handle : bucket)
                originalRelease(resourceMgr, handle);
        }
        pool_.clear();
        totalPooled_ = 0;
    }

    struct Stats { uint64_t hits = 0, misses = 0, evictions = 0; };
    const Stats& stats() const { return stats_; }

private:
    static uint32_t roundUpPow2(uint32_t v) {
        if (v == 0) {
            return 64;
        }
        v--; v |= v >> 1; v |= v >> 2; v |= v >> 4; v |= v >> 8; v |= v >> 16; v++;
        return v < 64 ? 64 : v;
    }
    static VBPoolKey makeKey(uint32_t stride, uint32_t count) {
        return { stride, roundUpPow2(count) };
    }

    std::unordered_map<VBPoolKey, std::vector<uint32_t>, VBPoolKeyHash> pool_;
    size_t totalPooled_ = 0;
    Stats stats_;
};

// Global state
namespace render_hook {

static CreateVB_t       original_CreateVB = nullptr;
static ReleaseVB_t      original_ReleaseVB = nullptr;
static BatcherFlush_t   original_BatcherFlush = nullptr;
static RendererDraw_t   original_RendererDraw = nullptr;

static GetResource_t    g_GetResource = nullptr;
static IsRenderThread_t g_IsRenderThread = nullptr;
static void*            g_renderer = nullptr;

inline bool g_enableBufferPool = false;

#ifdef _WIN32
static PFNGLBINDBUFFERPROC    g_glBindBuffer    = nullptr;
static PFNGLBUFFERSUBDATAPROC g_glBufferSubData = nullptr;
static bool g_glFunctionsResolved = false;

void SetRenderHookGlFunctionsWithNew() {
    g_glBindBuffer = &glBindBuffer;
    g_glBufferSubData = &glBufferSubData;
    g_glFunctionsResolved = true;
    spdlog::info("[RenderHook] GL functions set by ANGLE hijack (static link)");
}

// If GameOpenGl already set the GL function pointers (ANGLE hijack active),
// we use those. Otherwise fall back to the game's original libGLESv2.dll.
inline bool ensureGlFunctions() {
    if (g_glFunctionsResolved) return (g_glBindBuffer && g_glBufferSubData);
    g_glFunctionsResolved = true;
    auto hGLESv2 = GetModuleHandleA("libGLESv2.dll");
    if (hGLESv2) {
        g_glBindBuffer    = reinterpret_cast<PFNGLBINDBUFFERPROC>(GetProcAddress(hGLESv2, "glBindBuffer"));
        g_glBufferSubData = reinterpret_cast<PFNGLBUFFERSUBDATAPROC>(GetProcAddress(hGLESv2, "glBufferSubData"));
    }
    if (!g_glBindBuffer || !g_glBufferSubData) {
        spdlog::warn("[RenderHook] could not resolve GL functions — pool disabled");
        g_enableBufferPool = false;
        return false;
    }
    spdlog::info("[RenderHook] GL functions resolved from libGLESv2.dll (no ANGLE hijack)");
    return true;
}
#endif

#if defined(_WIN32)
inline constexpr size_t kVBResourceMgrOffset = 0x1a8;
#elif defined(__APPLE__)
inline constexpr size_t kVBResourceMgrOffset = 0x1a8; // TODO: verify macOS offset
#else
inline constexpr size_t kVBResourceMgrOffset = 0x1a8; // TODO: verify Linux offset
#endif

inline VertexBufferPool  g_vbPool;

#ifndef ENABLE_RENDER_HOOK_STATS
#define ENABLE_RENDER_HOOK_STATS 0
#endif

#if ENABLE_RENDER_HOOK_STATS
inline constexpr uint32_t STATS_LOG_INTERVAL = 600;
inline uint32_t g_frameCounter = 0;

inline void logStatsIfNeeded();
#else
inline void logStatsIfNeeded() {}
#endif

// Phase 1: CreateVB hook — acquire from pool or fall through to original
inline void* hooked_CreateVB(void* renderer, eUsageType usage, uint32_t stride,
                             uint32_t count, const void* data, bool shadow) {
    if (!g_renderer) g_renderer = renderer;

    if (g_enableBufferPool && usage == eUsageType::STREAM_DRAW
        && g_GetResource && g_IsRenderThread && g_IsRenderThread()) {
#ifdef _WIN32
        if (!ensureGlFunctions()) return original_CreateVB(renderer, usage, stride, count, data, shadow);
#endif
        void* pooled = g_vbPool.acquire(stride, count);
        if (pooled) {
            uint32_t handle = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(pooled));
            void* vbMgr = *reinterpret_cast<void**>(reinterpret_cast<char*>(renderer) + kVBResourceMgrOffset);
            auto* hwBuf = reinterpret_cast<HWBuffer*>(g_GetResource(vbMgr, handle));
            if (hwBuf && data) {
#ifdef _WIN32
                hwBuf->count = count;
                g_glBindBuffer(GL_ARRAY_BUFFER_CONST, hwBuf->glBufferID);
                g_glBufferSubData(GL_ARRAY_BUFFER_CONST, 0,
                                  static_cast<intptr_t>(stride) * count, data);
#else
                using UploadData_t = void (*)(void*, const void*);
                auto uploadFn = reinterpret_cast<UploadData_t*>(hwBuf->vtable)[1];
                uploadFn(hwBuf, data);
#endif
            }
            return pooled;
        }
    }
    return original_CreateVB(renderer, usage, stride, count, data, shadow);
}

// Phase 1: Release hook — pool the VB instead of destroying it
// Only pool STREAM_DRAW buffers — STATIC_DRAW (UI, ocean) must go through normal release
inline void hooked_ReleaseVB(void* resourceMgr, uint32_t handle) {
    if (g_enableBufferPool && g_GetResource && g_IsRenderThread && g_IsRenderThread()) {
        auto* hwBuf = reinterpret_cast<HWBuffer*>(g_GetResource(resourceMgr, handle));
        if (hwBuf && hwBuf->usageType == eUsageType::STREAM_DRAW
            && g_vbPool.release(handle, hwBuf->stride, hwBuf->count))
            return;
    }
    original_ReleaseVB(resourceMgr, handle);
}

// Batcher::Flush hook — passthrough + periodic stats logging
inline void hooked_BatcherFlush(void* batcher) {
    original_BatcherFlush(batcher);
    logStatsIfNeeded();
}

#if ENABLE_RENDER_HOOK_STATS
inline void logStatsIfNeeded() {
    if (++g_frameCounter % STATS_LOG_INTERVAL != 0) return;
    if (g_enableBufferPool) {
        const auto& s = g_vbPool.stats();
        spdlog::info("[RenderHook] VBPool hits={} misses={} evictions={} hitRate={:.1f}%",
                     s.hits, s.misses, s.evictions,
                     (s.hits + s.misses) > 0 ? 100.0 * s.hits / (s.hits + s.misses) : 0.0);
    }
}
#endif

} // namespace render_hook

void InstallRenderHooks() {
#ifndef _WIN32
    return;
#endif
    using namespace render_signatures;
    using namespace render_hook;

    auto mainPath = gum_module_get_path(gum_process_get_main_module());
    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
 
    if (GetResource_sig.scan(mainPath)) {
        g_GetResource = reinterpret_cast<GetResource_t>(GetResource_sig.target_address);
        spdlog::info("[RenderHook] resolved GetResource at {}", reinterpret_cast<void*>(GetResource_sig.target_address));
    } else {
        spdlog::warn("[RenderHook] GetResource signature not found — pool disabled");
        g_enableBufferPool = false;
    }

    if (IsRenderThread_sig.scan(mainPath)) {
        g_IsRenderThread = reinterpret_cast<IsRenderThread_t>(IsRenderThread_sig.target_address);
        spdlog::info("[RenderHook] resolved IsRenderThread at {}", reinterpret_cast<void*>(IsRenderThread_sig.target_address));
    } else {
        spdlog::warn("[RenderHook] IsRenderThread signature not found — pool disabled");
        g_enableBufferPool = false;
    }

    if (CreateVB_sig.scan(mainPath)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(CreateVB_sig.target_address),
            reinterpret_cast<void*>(&hooked_CreateVB),
            nullptr,
            reinterpret_cast<void**>(&original_CreateVB));
        if (r == GUM_REPLACE_OK)
            spdlog::info("[RenderHook] hooked CreateVB at {}", reinterpret_cast<void*>(CreateVB_sig.target_address));
        else
            spdlog::error("[RenderHook] failed to hook CreateVB: {}", static_cast<int>(r));
    } else {
        spdlog::warn("[RenderHook] CreateVB signature not found");
    }

    if (ReleaseVB_sig.scan(mainPath)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(ReleaseVB_sig.target_address),
            reinterpret_cast<void*>(&hooked_ReleaseVB),
            nullptr,
            reinterpret_cast<void**>(&original_ReleaseVB));
        if (r == GUM_REPLACE_OK)
            spdlog::info("[RenderHook] hooked ReleaseVB at {}", reinterpret_cast<void*>(ReleaseVB_sig.target_address));
        else
            spdlog::error("[RenderHook] failed to hook ReleaseVB: {}", static_cast<int>(r));
    } else {
        spdlog::warn("[RenderHook] ReleaseVB signature not found");
    }

    if (BatcherFlush_sig.scan(mainPath)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(BatcherFlush_sig.target_address),
            reinterpret_cast<void*>(&hooked_BatcherFlush),
            nullptr,
            reinterpret_cast<void**>(&original_BatcherFlush));
        if (r == GUM_REPLACE_OK)
            spdlog::info("[RenderHook] hooked BatcherFlush at {}", reinterpret_cast<void*>(BatcherFlush_sig.target_address));
        else
            spdlog::error("[RenderHook] failed to hook BatcherFlush: {}", static_cast<int>(r));
    } else {
        spdlog::warn("[RenderHook] BatcherFlush signature not found");
    }
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_set_vbpool_enabled(bool enable) {
    render_hook::g_enableBufferPool = enable;
    spdlog::info("[RenderHook] VB Pool {}", enable ? "enabled" : "disabled");
}
