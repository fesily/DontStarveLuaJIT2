#include "GameRenderHook.hpp"
#include "BufferNamePool.hpp"
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

// HWBuffer binary layout — validated against Windows x64 binary via Ghidra.
// macOS x64 (semantic baseline): same offsets confirmed.
// Windows x64 (landing target): stride@+0x08, count@+0x0C, glBufferID@+0x10, usageType@+0x14
struct HWBuffer {
    void*       vtable;      // +0x00
    uint32_t    stride;      // +0x08
    uint32_t    count;       // +0x0C
    uint32_t    glBufferID;  // +0x10
    eUsageType  usageType;   // +0x14
};
static_assert(offsetof(HWBuffer, stride)     == 0x08);
static_assert(offsetof(HWBuffer, count)      == 0x0C);
static_assert(offsetof(HWBuffer, glBufferID) == 0x10);
static_assert(offsetof(HWBuffer, usageType)  == 0x14);

// Batcher::Flush(this)
using BatcherFlush_t = void (*)(void* batcher);

// Signature definitions — byte patterns from Ghidra/IDA.
namespace render_signatures {

// HWBuffer::Init(this, const void* data)
// macOS x86: 0x001c6338 | Windows x64: 0x1403e69f0
// Unique: confirmed 1 match in target binary
inline function_relocation::MemorySignature HWBufferInit_sig{
#ifdef _WIN32
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 48 89 7C 24 20 41 54 48 83 EC 20 4C 8B E2 48 8D 51 10 48 8B E9 B9 01 00 00 00", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

// HWBuffer::~HWBuffer() non-deleting dtor
// macOS x86: vtable 00457758 slot[0] = 001c62bc | Windows x64: 0x1403e68e0
// Unique: confirmed 1 match in target binary
// Strategy: zero glBufferID before calling original → glDeleteBuffers(1, &0) is a no-op in OpenGL
inline function_relocation::MemorySignature HWBufferDtor_sig{
#ifdef _WIN32
    "40 53 48 83 EC 20 48 8D 05 ?? ?? ?? ?? 48 8D 51 10 48 8B D9 48 89 01 B9 01 00 00 00", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

// Batcher::Flush(this)
// macOS: 0x100167c6c | Windows: 0x140036360
inline function_relocation::MemorySignature BatcherFlush_sig{
#ifdef _WIN32
    "4C 8B DC 49 89 6B 18 57 48 83 EC 70 48 8B 51 78 48 BD AB AA AA AA AA AA AA 2A", 0
#elif defined(__linux__)
    "TODO_FILL_LINUX_PATTERN", 0
#elif defined(__APPLE__)
    "TODO_FILL_MACOS_PATTERN", 0
#endif
};

} // namespace render_signatures

// GL constants (ANGLE/GLES2 compatible)
static constexpr uint32_t GL_ARRAY_BUFFER_TARGET         = 0x8892u; // GL_ARRAY_BUFFER
static constexpr uint32_t GL_ELEMENT_ARRAY_BUFFER_TARGET = 0x8893u; // GL_ELEMENT_ARRAY_BUFFER

namespace render_hook {

// Hook trampoline pointers
static void (*original_HWBufferInit)(void* hwBuffer, const void* data) = nullptr;
static void (*original_HWBufferDtor)(void* hwBuffer)                   = nullptr;
static BatcherFlush_t original_BatcherFlush                            = nullptr;

// GL function pointers (resolved from ANGLE / libGLESv2.dll)
using glGenBuffers_t   = void (*)(GLsizei n, GLuint* buffers);
using glDeleteBuffers_t = void (*)(GLsizei n, const GLuint* buffers);
using glBindBuffer_t   = void (*)(GLenum target, GLuint buffer);
using glBufferData_t   = void (*)(GLenum target, GLsizeiptr size, const void* data, GLenum usage);

static glGenBuffers_t    g_glGenBuffers    = nullptr;
static glDeleteBuffers_t g_glDeleteBuffers = nullptr;
static glBindBuffer_t    g_glBindBuffer    = nullptr;
static glBufferData_t    g_glBufferData    = nullptr;
static bool              g_glFunctionsResolved = false;

inline bool g_enableBufferPool = false;

// Pool instance — pools raw GL buffer names (GLuint) by (target, usageType, capacityBucket)
inline BufferNamePool g_bufferNamePool;

#ifdef _WIN32
void SetRenderHookGlFunctionsWithNew() {
    g_glGenBuffers    = &glGenBuffers;
    g_glDeleteBuffers = &glDeleteBuffers;
    g_glBindBuffer    = &glBindBuffer;
    g_glBufferData    = &glBufferData;
    g_glFunctionsResolved = true;
    spdlog::info("[RenderHook] GL functions set by ANGLE hijack (static link)");
}

inline bool ensureGlFunctions() {
    if (g_glFunctionsResolved) {
        return g_glGenBuffers && g_glDeleteBuffers && g_glBindBuffer && g_glBufferData;
    }
    g_glFunctionsResolved = true;
    auto hGLESv2 = GetModuleHandleA("libGLESv2.dll");
    if (hGLESv2) {
        g_glGenBuffers    = reinterpret_cast<glGenBuffers_t>(GetProcAddress(hGLESv2, "glGenBuffers"));
        g_glDeleteBuffers = reinterpret_cast<glDeleteBuffers_t>(GetProcAddress(hGLESv2, "glDeleteBuffers"));
        g_glBindBuffer    = reinterpret_cast<glBindBuffer_t>(GetProcAddress(hGLESv2, "glBindBuffer"));
        g_glBufferData    = reinterpret_cast<glBufferData_t>(GetProcAddress(hGLESv2, "glBufferData"));
    }
    if (!g_glGenBuffers || !g_glDeleteBuffers || !g_glBindBuffer || !g_glBufferData) {
        spdlog::warn("[RenderHook] could not resolve GL functions — pool disabled");
        g_enableBufferPool = false;
        return false;
    }
    spdlog::info("[RenderHook] GL functions resolved from libGLESv2.dll");
    return true;
}
#endif

static uint32_t roundUpPow2_min64(uint32_t v) noexcept {
    if (v == 0) return 64u;
    v--; v |= v>>1; v |= v>>2; v |= v>>4; v |= v>>8; v |= v>>16; v++;
    return v < 64u ? 64u : v;
}

static void doGlDeleteBuffers(uint32_t count, const uint32_t* names) {
#ifdef _WIN32
    if (g_glDeleteBuffers)
        g_glDeleteBuffers(static_cast<GLsizei>(count), names);
#else
    glDeleteBuffers(static_cast<GLsizei>(count), names);
#endif
}

inline void hooked_HWBufferInit(void* hwBuffer, const void* data) {
    if (!g_enableBufferPool) {
        original_HWBufferInit(hwBuffer, data);
        return;
    }
#ifdef _WIN32
    if (!ensureGlFunctions()) {
        original_HWBufferInit(hwBuffer, data);
        return;
    }
#endif

    auto* buf = reinterpret_cast<HWBuffer*>(hwBuffer);

    if (buf->usageType != eUsageType::STREAM_DRAW) {
        original_HWBufferInit(hwBuffer, data);
        return;
    }

    // vtable slot [2] = TargetType(): VertexBuffer→0x8892, IndexBuffer→0x8893
    // MSVC x64 ABI: slot[0]=deleting dtor, slot[1]=Init, slot[2]=TargetType
    // (macOS x86 Itanium ABI has 4 slots: non-deleting dtor, deleting dtor, Init, TargetType)
    using TargetType_t = uint32_t (*)(void*);
    const uint32_t target = reinterpret_cast<TargetType_t*>(buf->vtable)[2](hwBuffer);

    if (target != GL_ARRAY_BUFFER_TARGET && target != GL_ELEMENT_ARRAY_BUFFER_TARGET) {
        original_HWBufferInit(hwBuffer, data);
        return;
    }

    const uint32_t byteSize = buf->stride * buf->count;
    const uint32_t pooledName = g_bufferNamePool.acquire(target, static_cast<uint32_t>(buf->usageType), byteSize);

    if (pooledName != 0) {
        buf->glBufferID = pooledName;
        g_glBindBuffer(target, pooledName);
        if (data) {
            // Renderer::GetGLUsage(STREAM_DRAW) returns GL_STREAM_DRAW = 0x88E0
            g_glBufferData(target, static_cast<GLsizeiptr>(byteSize), data, 0x88E0u);
        }
        g_bufferNamePool.registerName(pooledName, target,
                                      static_cast<uint32_t>(buf->usageType),
                                      roundUpPow2_min64(byteSize));
        return;
    }

    original_HWBufferInit(hwBuffer, data);

    if (buf->glBufferID != 0) {
        g_bufferNamePool.registerName(buf->glBufferID, target,
                                      static_cast<uint32_t>(buf->usageType),
                                      roundUpPow2_min64(byteSize));
    }
}

inline void hooked_HWBufferDtor(void* hwBuffer) {
    auto* buf = reinterpret_cast<HWBuffer*>(hwBuffer);
    const uint32_t name = buf->glBufferID;

    if (g_enableBufferPool && name != 0) {
        const BufferNamePool::SideMapEntry* entry = g_bufferNamePool.lookupSideMap(name);
        if (entry) {
            const uint32_t target    = entry->target;
            const uint32_t usageType = entry->usageType;
            const uint32_t bucket    = entry->capacityBucket;

            g_bufferNamePool.unregisterName(name);

            if (g_bufferNamePool.releaseWithEvict(name, target, usageType, bucket, doGlDeleteBuffers)) {
                // Zeroing glBufferID makes the original dtor's glDeleteBuffers(1, &0) a no-op.
                // OpenGL spec §4.4: names of 0 are silently ignored by glDeleteBuffers.
                buf->glBufferID = 0;
            }
        }
    }

    original_HWBufferDtor(hwBuffer);
}

// Batcher::Flush hook — passthrough + periodic stats logging
inline void hooked_BatcherFlush(void* batcher) {
    original_BatcherFlush(batcher);
#define ENABLE_RENDER_HOOK_STATS 1
#if ENABLE_RENDER_HOOK_STATS
    static uint32_t s_frameCounter = 0;
    static constexpr uint32_t kLogInterval = 600;
    if (++s_frameCounter % kLogInterval == 0 && g_enableBufferPool) {
        const auto& s = g_bufferNamePool.stats();
        const uint64_t total = s.hits + s.misses;
        spdlog::info("[RenderHook] Pool hits={} misses={} evictions={} hitRate={:.1f}% "
                     "reusedBytes={}KB genSaved={} deleteSaved={} pooled={} poolBytes={}KB",
                     s.hits, s.misses, s.evictions,
                     total > 0 ? 100.0 * s.hits / total : 0.0,
                     s.reusedBytes / 1024,
                     s.genSaved, s.deleteSaved,
                     g_bufferNamePool.totalPooled(),
                     g_bufferNamePool.totalBytes() / 1024);
    }
#endif
}

static bool g_hooksInstalled = false;

static bool installPoolHooks() {
    using namespace render_signatures;

    auto mainPath    = gum_module_get_path(gum_process_get_main_module());
    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();

    bool initOk = false;
    bool dtorOk = false;

    if (HWBufferInit_sig.scan(mainPath)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(HWBufferInit_sig.target_address),
            reinterpret_cast<void*>(static_cast<void (*)(void*, const void*)>(&hooked_HWBufferInit)),
            nullptr,
            reinterpret_cast<void**>(&original_HWBufferInit));
        if (r == GUM_REPLACE_OK) {
            spdlog::info("[RenderHook] hooked HWBuffer::Init at {:#x}", HWBufferInit_sig.target_address);
            initOk = true;
        } else {
            spdlog::error("[RenderHook] failed to hook HWBuffer::Init: {}", static_cast<int>(r));
        }
    } else {
        spdlog::warn("[RenderHook] HWBuffer::Init signature not found");
    }

    if (HWBufferDtor_sig.scan(mainPath)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(HWBufferDtor_sig.target_address),
            reinterpret_cast<void*>(static_cast<void (*)(void*)>(&hooked_HWBufferDtor)),
            nullptr,
            reinterpret_cast<void**>(&original_HWBufferDtor));
        if (r == GUM_REPLACE_OK) {
            spdlog::info("[RenderHook] hooked HWBuffer::~HWBuffer at {:#x}", HWBufferDtor_sig.target_address);
            dtorOk = true;
        } else {
            spdlog::error("[RenderHook] failed to hook HWBuffer::~HWBuffer: {}", static_cast<int>(r));
        }
    } else {
        spdlog::warn("[RenderHook] HWBuffer::~HWBuffer signature not found");
    }

    if (!initOk || !dtorOk) {
        spdlog::warn("[RenderHook] hook installation incomplete — pool disabled");
        // Revert partially installed hook to avoid Init/dtor asymmetry
        if (initOk)
            gum_interceptor_revert(interceptor, reinterpret_cast<void*>(HWBufferInit_sig.target_address));
        if (dtorOk)
            gum_interceptor_revert(interceptor, reinterpret_cast<void*>(HWBufferDtor_sig.target_address));
        return false;
    }

    spdlog::info("[RenderHook] HWBuffer pool hooks installed successfully");
    return true;
}

static void uninstallPoolHooks() {
    using namespace render_signatures;
    auto interceptor = InjectorCtx::instance()->GetGumInterceptor();

    gum_interceptor_revert(interceptor, reinterpret_cast<void*>(HWBufferInit_sig.target_address));
    gum_interceptor_revert(interceptor, reinterpret_cast<void*>(HWBufferDtor_sig.target_address));
    original_HWBufferInit = nullptr;
    original_HWBufferDtor = nullptr;
    spdlog::info("[RenderHook] HWBuffer pool hooks reverted");
}

} // namespace render_hook

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_set_vbpool_enabled(bool enable) {
    using namespace render_hook;
    using namespace render_signatures;
    if (enable && !g_hooksInstalled) {
        if (!InjectorCtx::instance()->DontStarveInjectorIsClient) {
            spdlog::info("[RenderHook] not in client process, skipping render hooks");
            return;
        }
        if (!ensureGlFunctions()) {
            spdlog::warn("[RenderHook] GL functions unavailable — pool not enabled");
            return;
        }
        if (installPoolHooks()) {
            g_hooksInstalled = true;
            g_enableBufferPool = true;

            auto mainPath    = gum_module_get_path(gum_process_get_main_module());
            auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
            if (BatcherFlush_sig.scan(mainPath)) {
                auto r = gum_interceptor_replace(
                    interceptor,
                    reinterpret_cast<void*>(BatcherFlush_sig.target_address),
                    reinterpret_cast<void*>(&hooked_BatcherFlush),
                    nullptr,
                    reinterpret_cast<void**>(&original_BatcherFlush));
                if (r == GUM_REPLACE_OK)
                    spdlog::info("[RenderHook] hooked Batcher::Flush at {:#x}", BatcherFlush_sig.target_address);
                else
                    spdlog::warn("[RenderHook] failed to hook Batcher::Flush: {}", static_cast<int>(r));
            }
            spdlog::info("[RenderHook] pool enabled");
        }
    } else if (!enable && g_hooksInstalled) {
        g_enableBufferPool = false;
        g_bufferNamePool.drainAll(doGlDeleteBuffers);
        uninstallPoolHooks();
        if (original_BatcherFlush) {
            auto interceptor = InjectorCtx::instance()->GetGumInterceptor();
            gum_interceptor_revert(interceptor, reinterpret_cast<void*>(BatcherFlush_sig.target_address));
            original_BatcherFlush = nullptr;
        }
        g_hooksInstalled = false;
        spdlog::info("[RenderHook] pool disabled and hooks reverted");
    }
}
