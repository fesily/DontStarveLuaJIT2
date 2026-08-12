// JitterProbeHooks.cpp — low-overhead Win x64 probes for prediction-OFF jitter.
//
// Design (post test.log lesson):
//   - NO I/O on hot path. fprintf/spdlog per SetPos killed the frame (thousands/sec).
//   - Ring buffer of compact events; flush on timer / demand / disable.
//   - Filter: only log when |Δpos| > eps OR op is Deserialize/EnablePred, and
//     optionally only for a single tracked transform (local player).
//
// Path: pred OFF → Deserialize → Teleport/SetPosition. hist=null, pred=0.
// Also: AppFrame dt + ActualCacheRender/DrawCacheRender wall timings (render phase).

#include "config/InjectorHostConfig.hpp"
#include "MemorySignature.hpp"
#include "ctx.hpp"

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <string>
#include <ctime>
#include <cstring>
#include <mutex>

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#ifdef _WIN32

namespace {

using wall_clock = std::chrono::steady_clock;

enum class Op : uint8_t {
    SetPos = 1,
    Teleport = 2,
    Deserialize = 3,
    DeserializePost = 4,
    EnablePred = 5,
    // Frame / render probes (1+2)
    FrameBegin = 6,   // application frame entry (dt in x)
    FrameEnd = 7,     // application frame exit (dt wall in x, phases in y)
    CacheRender = 8,  // ActualCacheRender begin/end (x=dt_ms of cache phase if end)
    DrawCache = 9,    // DrawCacheRender begin/end
    AnimPreserve = 10, // flAnimTime preserved (x=saved_time, y=server_time, z=delta)
};

struct Event {
    uint64_t t_ns;
    uint64_t self;
    float x, y, z;
    float ox, oy, oz; // old / pre
    Op op;
    uint8_t respect;
    int8_t pred;
    uint8_t flags; // bit0: filtered local-only match
};

static constexpr size_t kRing = 4096;
static constexpr float kEps = 1e-4f; // ignore no-op SetPos

std::atomic_bool g_enabled{false};
std::atomic_bool g_hooks_installed{false};
std::atomic_bool g_local_only{true};
char g_vm_tag_buf[32]{"run"};
std::mutex g_vm_tag_mu;
std::atomic_uint64_t g_track_self{0}; // 0 = not set; when set, only this transform*
std::atomic_uint64_t g_seq{0};
std::atomic_uint64_t g_dropped{0};
std::atomic_uint64_t g_seen{0};

Event g_ring[kRing];
std::atomic_uint32_t g_head{0}; // next write
std::mutex g_flush_mu;

static uint64_t now_ns() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            wall_clock::now().time_since_epoch())
            .count());
}

static const char *op_name(Op op) {
    switch (op) {
    case Op::SetPos: return "SetPos";
    case Op::Teleport: return "Teleport";
    case Op::Deserialize: return "Deserialize";
    case Op::DeserializePost: return "DeserializePost";
    case Op::EnablePred: return "EnablePred";
    case Op::FrameBegin: return "FrameBegin";
    case Op::FrameEnd: return "FrameEnd";
    case Op::CacheRender: return "CacheRender";
    case Op::DrawCache: return "DrawCache";
    case Op::AnimPreserve: return "AnimPreserve";
    }
    return "?";
}

static bool is_tracked(void *self) {
    const uint64_t track = g_track_self.load(std::memory_order_relaxed);
    if (track == 0) {
        // Not bound yet: accept all for first-pass entity discovery, but still
        // drop no-op SetPos in push().
        return !g_local_only.load(std::memory_order_relaxed);
    }
    return reinterpret_cast<uint64_t>(self) == track;
}

static void push(Op op, void *self, float x, float y, float z,
                 float ox, float oy, float oz, uint8_t respect, int8_t pred) {
    if (!g_enabled.load(std::memory_order_relaxed)) {
        return;
    }
    g_seen.fetch_add(1, std::memory_order_relaxed);

    // Always keep EnablePred / Deserialize*; SetPos/Teleport only if moved or tracked.
    const bool moved = (std::fabs(x - ox) > kEps) || (std::fabs(z - oz) > kEps) ||
                       (std::fabs(y - oy) > kEps);
    if (op == Op::SetPos && !moved) {
        return; // pure no-op write spam
    }
    if (g_local_only.load(std::memory_order_relaxed) &&
        op != Op::EnablePred) {
        const uint64_t track = g_track_self.load(std::memory_order_relaxed);
        if (track != 0 && reinterpret_cast<uint64_t>(self) != track) {
            return;
        }
        // track==0: buffer sparingly — only Deserialize family until bound
        if (track == 0 && (op == Op::SetPos || op == Op::Teleport)) {
            // sample 1/64 of untracked SetPos/Teleport for discovery
            if ((g_seen.load(std::memory_order_relaxed) & 63u) != 0) {
                return;
            }
        }
    }

    Event e{};
    e.t_ns = now_ns();
    e.self = reinterpret_cast<uint64_t>(self);
    e.x = x;
    e.y = y;
    e.z = z;
    e.ox = ox;
    e.oy = oy;
    e.oz = oz;
    e.op = op;
    e.respect = respect;
    e.pred = pred;
    e.flags = (g_track_self.load(std::memory_order_relaxed) == e.self) ? 1 : 0;

    const uint32_t i = g_head.fetch_add(1, std::memory_order_relaxed) % kRing;
    // Single-writer per slot under wrap is racy but acceptable for diagnostics.
    g_ring[i] = e;
    g_seq.fetch_add(1, std::memory_order_relaxed);
}

// Lightweight marker event (frame/render). Uses Event.x/y/z for scalars:
//   FrameBegin: x=dt_s (clamped), y=0, z=0
//   FrameEnd:   x=frame_wall_ms, y=cache_ms, z=draw_ms
//   CacheRender begin: x=0; end: x=cache_ms
//   DrawCache begin: x=0; end: x=draw_ms
// self pointer stores game/app object when available (may be 0).
static void push_marker(Op op, void *self, float x, float y, float z) {
    if (!g_enabled.load(std::memory_order_relaxed)) {
        return;
    }
    g_seen.fetch_add(1, std::memory_order_relaxed);
    Event e{};
    e.t_ns = now_ns();
    e.self = reinterpret_cast<uint64_t>(self);
    e.x = x;
    e.y = y;
    e.z = z;
    e.ox = e.oy = e.oz = 0;
    e.op = op;
    e.respect = 0;
    e.pred = -1;
    e.flags = 2; // marker bit
    const uint32_t i = g_head.fetch_add(1, std::memory_order_relaxed) % kRing;
    g_ring[i] = e;
    g_seq.fetch_add(1, std::memory_order_relaxed);
}

// Per-frame wall timing (thread-local: main thread only in practice).
struct FrameProbeState {
    uint64_t frame_t0 = 0;
    uint64_t cache_t0 = 0;
    uint64_t draw_t0 = 0;
    float last_dt_s = 0;
    float last_cache_ms = 0;
    float last_draw_ms = 0;
    bool in_frame = false;
};
static thread_local FrameProbeState tls_frame{};

static float ns_to_ms(uint64_t a, uint64_t b) {
    if (b <= a) {
        return 0.f;
    }
    return static_cast<float>(b - a) * 1e-6f;
}

// ---------------------------------------------------------------------------
// Signatures
// ---------------------------------------------------------------------------

static function_relocation::MemorySignature setpos_sig{
    "48 89 5C 24 08 "
    "57 "
    "48 83 EC 30 "
    "F3 0F 10 41 38 "
    "33 C0 "
    "48 8B F9",
    0};

static function_relocation::MemorySignature teleport_sig{
    "48 8B C4 "
    "48 89 58 08 "
    "48 89 70 10 "
    "57 "
    "48 81 EC 90 00 00 00 "
    "48 83 B9 98 00 00 00 00 "
    "0F 29 70 E8",
    0};

static function_relocation::MemorySignature deserialize_sig{
    "53 "
    "57 "
    "48 83 EC 38 "
    "83 3A 00 "
    "48 8B FA "
    "48 8B D9 "
    "0F 84",
    0};

static function_relocation::MemorySignature enable_pred_sig{
    "53 "
    "48 83 EC 30 "
    "45 33 C0 "
    "48 8B D9 "
    "48 8B 89 98 01 00 00",
    0};

// Application frame (MessagePump / CacheRender / DrawCacheRender host).
// FUN_140004230: PUSH RBX; PUSH RDI; SUB RSP,0x68; MOVSS XMM0,[imm]; MOVAPS [RSP+50],XMM6
// FUN_140004230 Application::OnFrame (MessagePump/CacheRender/DrawCache host).
// MOVSS XMM0,[rip+disp32] needs 4-byte wildcard — previous pattern missed them.
static function_relocation::MemorySignature app_frame_sig{
    "53 "
    "57 "
    "48 83 EC 68 "
    "F3 0F 10 05 ?? ?? ?? ?? "
    "0F 29 74 24 50",
    0};

// ActualCacheRender FUN_140013360:
// MOV RAX,RSP; MOV [RAX+8],RBX; PUSH RDI; SUB RSP,0xC0; MOV RDI,RDX; MOV RBX,RCX
static function_relocation::MemorySignature actual_cache_sig{
    "48 8B C4 "
    "48 89 58 08 "
    "57 "
    "48 81 EC C0 00 00 00 "
    "48 8B FA "
    "48 8B D9",
    0};

// DrawCacheRender FUN_140014a50:
// MOV [RSP+18],RBX; MOV [RSP+20],RSI; PUSH RDI; SUB RSP,0x50; MOV RDI,RDX; MOV RBX,RCX
static function_relocation::MemorySignature draw_cache_sig{
    "48 89 5C 24 18 "
    "48 89 74 24 20 "
    "57 "
    "48 83 EC 50 "
    "48 8B FA "
    "48 8B D9",
    0};

using SetPosition_t = void(__fastcall *)(void *self, const float *pos);
using Teleport_t = void(__fastcall *)(void *self, const float *pos, uint8_t respect);
using Deserialize_t = void(__fastcall *)(void *self, void *bitstream);
using EnablePred_t = void(__fastcall *)(void *self, uint8_t enable);
// MSVC x64: first float/double in XMM1 for member/thiscall-like free functions with float arg.
using AppFrame_t = bool(__fastcall *)(void *self, float dt);
using ActualCache_t = void(__fastcall *)(void *self, void *cache, float dt);
using DrawCache_t = void(__fastcall *)(void *self, float *cache);

// cAnimStateComponent::Deserialize (Win x64) — FUN_14009fc60
// Prevents server from overwriting local flAnimTime for tracked entity.
// cAnimStateComponent::Deserialize (Win x64)
// SUB RSP,0xB8 uses 81 EC (32-bit imm) not 83 EC (8-bit, only for 0x00-0x7F).
static function_relocation::MemorySignature animstate_deserialize_sig{
    "48 8B C4 "
    "56 "
    "57 "
    "48 81 EC B8 00 00 00 "
    "83 3A 00 "
    "48 8B FA "
    "48 8B F1",
    0};

// cAnimStateComponent offsets (Win x64, from disasm)
static constexpr int ASC_ENTITY = 0x18;       // cEntity* back-ref
static constexpr int ASC_FL_ANIM_TIME = 0x28;  // float flAnimTime
static constexpr int ASC_P_ANIM_NODE = 0xF0;   // AnimNode*
static constexpr int ANIMNODE_FL_TIME = 0xF8;  // AnimNode::flTime (Win x64, macOS=0xBC+0x3C shift)

using AnimStateDeserialize_t = void(__fastcall *)(void *self, void *bitstream);
AnimStateDeserialize_t original_AnimStateDeserialize = nullptr;
// Inline patch state: force local_a0=true for local player in Deserialize.
// At function+0x45 (XOR BL,BL), gum_interceptor_attach intercepts and sets BL.
static uintptr_t g_local_a0_patch_addr = 0;

// Local player entity pointer (set from Lua via set_track_entity).
// When non-null, flAnimTime is preserved across Deserialize for this entity.
std::atomic_uint64_t g_local_player_entity{0};
// Diagnostics: count hook calls, entity matches, time preservations.
std::atomic_uint64_t g_anim_deserialize_calls{0};
std::atomic_uint64_t g_anim_entity_matches{0};
std::atomic_uint64_t g_anim_time_preserved{0};

SetPosition_t original_SetPosition = nullptr;
Teleport_t original_Teleport = nullptr;
Deserialize_t original_Deserialize = nullptr;
EnablePred_t original_EnablePred = nullptr;
AppFrame_t original_AppFrame = nullptr;
ActualCache_t original_ActualCache = nullptr;
DrawCache_t original_DrawCache = nullptr;

void __fastcall hooked_SetPosition(void *self, const float *pos) {
    if (g_enabled.load(std::memory_order_relaxed) && self && pos) {
        const float *old = reinterpret_cast<const float *>(
            reinterpret_cast<const char *>(self) + 0x38);
        push(Op::SetPos, self, pos[0], pos[1], pos[2], old[0], old[1], old[2], 0, -1);
    }
    original_SetPosition(self, pos);
}

void __fastcall hooked_Teleport(void *self, const float *pos, uint8_t respect) {
    if (g_enabled.load(std::memory_order_relaxed) && self && pos) {
        // Physics* self; transform at +0x28 → old local pos at transform+0x38
        float ox = 0, oy = 0, oz = 0;
        auto *xform = *reinterpret_cast<char **>(reinterpret_cast<char *>(self) + 0x28);
        if (xform) {
            const float *old = reinterpret_cast<const float *>(xform + 0x38);
            ox = old[0];
            oy = old[1];
            oz = old[2];
        }
        push(Op::Teleport, self, pos[0], pos[1], pos[2], ox, oy, oz, respect, -1);
    }
    original_Teleport(self, pos, respect);
}

void __fastcall hooked_Deserialize(void *self, void *bitstream) {
    float sx = 0, sy = 0, sz = 0;
    int pred = 0;
    if (g_enabled.load(std::memory_order_relaxed) && self) {
        const float *server = reinterpret_cast<const float *>(
            reinterpret_cast<const char *>(self) + 0x44);
        const float *local = reinterpret_cast<const float *>(
            reinterpret_cast<const char *>(self) + 0x38);
        pred = *reinterpret_cast<const int *>(
            reinterpret_cast<const char *>(self) + 0x1a4);
        sx = server[0];
        sy = server[1];
        sz = server[2];
        push(Op::Deserialize, self, sx, sy, sz, local[0], local[1], local[2], 0,
             static_cast<int8_t>(pred));
    }
    original_Deserialize(self, bitstream);
    if (g_enabled.load(std::memory_order_relaxed) && self) {
        const float *local = reinterpret_cast<const float *>(
            reinterpret_cast<const char *>(self) + 0x38);
        pred = *reinterpret_cast<const int *>(
            reinterpret_cast<const char *>(self) + 0x1a4);
        push(Op::DeserializePost, self, local[0], local[1], local[2], sx, sy, sz, 0,
             static_cast<int8_t>(pred));
    }
}

void __fastcall hooked_EnablePred(void *self, uint8_t enable) {
    if (g_enabled.load(std::memory_order_relaxed)) {
        push(Op::EnablePred, self, static_cast<float>(enable), 0, 0, 0, 0, 0, 0, -1);
    }
    original_EnablePred(self, enable);
}

bool __fastcall hooked_AppFrame(void *self, float dt) {
    if (g_enabled.load(std::memory_order_relaxed)) {
        tls_frame.frame_t0 = now_ns();
        tls_frame.in_frame = true;
        tls_frame.last_dt_s = dt;
        tls_frame.last_cache_ms = 0;
        tls_frame.last_draw_ms = 0;
        push_marker(Op::FrameBegin, self, dt, 0.f, 0.f);
    }
    const bool ret = original_AppFrame ? original_AppFrame(self, dt) : true;
    if (g_enabled.load(std::memory_order_relaxed) && tls_frame.in_frame) {
        const uint64_t t1 = now_ns();
        const float wall_ms = ns_to_ms(tls_frame.frame_t0, t1);
        push_marker(Op::FrameEnd, self, wall_ms, tls_frame.last_cache_ms, tls_frame.last_draw_ms);
        tls_frame.in_frame = false;
    }
    return ret;
}

void __fastcall hooked_ActualCache(void *self, void *cache, float dt) {
    if (g_enabled.load(std::memory_order_relaxed)) {
        tls_frame.cache_t0 = now_ns();
        push_marker(Op::CacheRender, self, 0.f, dt, 0.f); // begin: y=dt
    }
    if (original_ActualCache) {
        original_ActualCache(self, cache, dt);
    }
    if (g_enabled.load(std::memory_order_relaxed)) {
        const float ms = ns_to_ms(tls_frame.cache_t0, now_ns());
        tls_frame.last_cache_ms = ms;
        push_marker(Op::CacheRender, self, ms, 1.f, 0.f); // end: x=ms, y=1 marks end
    }
}

void __fastcall hooked_DrawCache(void *self, float *cache) {
    if (g_enabled.load(std::memory_order_relaxed)) {
        tls_frame.draw_t0 = now_ns();
        push_marker(Op::DrawCache, self, 0.f, 0.f, 0.f); // begin
    }
    if (original_DrawCache) {
        original_DrawCache(self, cache);
    }
    if (g_enabled.load(std::memory_order_relaxed)) {
        const float ms = ns_to_ms(tls_frame.draw_t0, now_ns());
        tls_frame.last_draw_ms = ms;
        push_marker(Op::DrawCache, self, ms, 1.f, 0.f); // end
    }
}

// Hook cAnimStateComponent::Deserialize: preserve flAnimTime for local player.
// Server overwrites flAnimTime on every incremental frame when prediction is OFF
// (ignoreApply=0 because IsPredictingMovement returns false). This causes visible
// animation "rewinds" ~0.35/s. We save flAnimTime before calling original, then
// restore it after, so anim hash/bank changes still apply but time stays local.
void __fastcall hooked_AnimStateDeserialize(void *self, void *bitstream) {
    if (!g_enabled.load(std::memory_order_relaxed) || !self) {
        if (original_AnimStateDeserialize) {
            original_AnimStateDeserialize(self, bitstream);
        }
        return;
    }
    g_anim_deserialize_calls.fetch_add(1, std::memory_order_relaxed);

    // Check if this anim component belongs to the local player entity.
    const uint64_t local_entity = g_local_player_entity.load(std::memory_order_relaxed);
    bool preserve_time = false;
    float saved_time = 0.f;
    float saved_animnode_time = 0.f;
    void *anim_node = nullptr;
    if (local_entity != 0) {
        auto *anim = static_cast<char *>(self);
        void *entity = *reinterpret_cast<void **>(anim + ASC_ENTITY);
        if (reinterpret_cast<uint64_t>(entity) == local_entity) {
            preserve_time = true;
            saved_time = *reinterpret_cast<float *>(anim + ASC_FL_ANIM_TIME);
            anim_node = *reinterpret_cast<void **>(anim + ASC_P_ANIM_NODE);
            if (anim_node) {
                saved_animnode_time = *reinterpret_cast<float *>(
                    static_cast<char *>(anim_node) + ANIMNODE_FL_TIME);
            }
            g_anim_entity_matches.fetch_add(1, std::memory_order_relaxed);
        }
    }

    // Call original Deserialize (applies all server state including flAnimTime).
    if (original_AnimStateDeserialize) {
        original_AnimStateDeserialize(self, bitstream);
    }

    // Only restore if the server's write was a RESET (server_time == 0).
    // If the server sent a real time value (server_time > 0), it's a legitimate
    // sync and we let it through. This prevents the feedback loop where
    // preserved time accumulates forever.
    if (preserve_time && self) {
        auto *anim = static_cast<char *>(self);
        float server_time = *reinterpret_cast<float *>(anim + ASC_FL_ANIM_TIME);
        bool was_reset = (server_time < 0.001f);  // server reset to ~0
        if (was_reset) {
            *reinterpret_cast<float *>(anim + ASC_FL_ANIM_TIME) = saved_time;
            if (anim_node) {
                *reinterpret_cast<float *>(
                    static_cast<char *>(anim_node) + ANIMNODE_FL_TIME) = saved_animnode_time;
            }
            g_anim_time_preserved.fetch_add(1, std::memory_order_relaxed);
        }
        push_marker(Op::AnimPreserve, self, saved_time, server_time,
                   server_time - saved_time);
    }
}



// local_a0 inline patch via gum_interceptor_attach.
// on_enter callback: check if RSI (cAnimStateComponent*) belongs to local player.
// If yes, set BL=1 (skip anim state writes). If no, leave BL=0.
static void local_a0_on_enter(GumInvocationContext *context, gpointer) {
    if (!g_enabled.load(std::memory_order_relaxed)) return;
    if (!context || !context->cpu_context) return;
    auto *cpu = context->cpu_context;
    auto *anim = reinterpret_cast<char *>(cpu->rsi);
    if (!anim) return;
    void *entity = *reinterpret_cast<void **>(anim + ASC_ENTITY);
    const uint64_t local = g_local_player_entity.load(std::memory_order_relaxed);
    if (local != 0 && reinterpret_cast<uint64_t>(entity) == local) {
        cpu->rbx |= 1;  // BL=1: skip anim state writes
    }
}
static GumInvocationListener *g_local_a0_listener = nullptr;

static void debug_log(const char *fmt, ...) {
    FILE *f = std::fopen("jitter_probe_install.log", "a");
    if (!f) return;
    va_list ap;
    va_start(ap, fmt);
    std::vfprintf(f, fmt, ap);
    va_end(ap);
    std::fclose(f);
}

bool install_one(GumInterceptor *interceptor, function_relocation::MemorySignature &sig,
                 void *hook, void **original_out, const char *name) {
    sig.only_one = true;
    sig.log = true;
    debug_log("[install_one] name=%s pattern=\"%s\" offset=%d\n", name, sig.pattern, sig.pattern_offset);
    if (!sig.scan(nullptr)) {
        debug_log("[install_one] SCAN FAILED: %s pattern=\"%s\"\n", name, sig.pattern);
        std::fprintf(stderr, "[JitterProbe] signature not found: %s\n", name);
        return false;
    }
    debug_log("[install_one] scan OK: %s target=0x%llx\n", name,
              static_cast<unsigned long long>(sig.target_address));
    auto r = gum_interceptor_replace(
        interceptor,
        reinterpret_cast<void *>(sig.target_address),
        hook,
        original_out,
        nullptr);
    if (r != GUM_REPLACE_OK) {
        debug_log("[install_one] REPLACE FAILED: %s rc=%d addr=0x%llx\n", name,
                  static_cast<int>(r),
                  static_cast<unsigned long long>(sig.target_address));
        std::fprintf(stderr, "[JitterProbe] replace failed %s: %d\n", name, static_cast<int>(r));
        return false;
    }
    debug_log("[install_one] HOOKED: %s at 0x%llx\n", name,
              static_cast<unsigned long long>(sig.target_address));
    std::fprintf(stderr, "[JitterProbe] hooked %s at %p\n", name,
                 reinterpret_cast<void *>(sig.target_address));
    return true;
}

bool install_hooks() {
    auto *ctx = InjectorCtx::instance();
    if (!ctx) {
        std::fprintf(stderr, "[JitterProbe] InjectorCtx unavailable\n");
        return false;
    }
    auto *interceptor = ctx->GetGumInterceptor();
    if (!interceptor) {
        std::fprintf(stderr, "[JitterProbe] GumInterceptor unavailable\n");
        return false;
    }
    (void)function_relocation::init_ctx();

    bool ok = true;
    ok &= install_one(interceptor, setpos_sig, reinterpret_cast<void *>(&hooked_SetPosition),
                      reinterpret_cast<void **>(&original_SetPosition), "SetPosition");
    ok &= install_one(interceptor, teleport_sig, reinterpret_cast<void *>(&hooked_Teleport),
                      reinterpret_cast<void **>(&original_Teleport), "Teleport");
    ok &= install_one(interceptor, deserialize_sig, reinterpret_cast<void *>(&hooked_Deserialize),
                      reinterpret_cast<void **>(&original_Deserialize), "Deserialize");
    ok &= install_one(interceptor, enable_pred_sig, reinterpret_cast<void *>(&hooked_EnablePred),
                      reinterpret_cast<void **>(&original_EnablePred), "EnableMovementPrediction");
    // Frame/render probes — soft-fail: authority hooks still useful if these miss.
    if (!install_one(interceptor, app_frame_sig, reinterpret_cast<void *>(&hooked_AppFrame),
                     reinterpret_cast<void **>(&original_AppFrame), "AppFrame")) {
        std::fprintf(stderr, "[JitterProbe] AppFrame probe unavailable\n");
    }
    if (!install_one(interceptor, actual_cache_sig, reinterpret_cast<void *>(&hooked_ActualCache),
                     reinterpret_cast<void **>(&original_ActualCache), "ActualCacheRender")) {
        std::fprintf(stderr, "[JitterProbe] ActualCacheRender probe unavailable\n");
    }
    if (!install_one(interceptor, draw_cache_sig, reinterpret_cast<void *>(&hooked_DrawCache),
                     reinterpret_cast<void **>(&original_DrawCache), "DrawCacheRender")) {
        std::fprintf(stderr, "[JitterProbe] DrawCacheRender probe unavailable\n");
    }
    // Inline patch: force local_a0=true for local player in Deserialize.
    // Skips PlayMode/AnimHash/AnimTime writes entirely — no save/restore.
    {
        uintptr_t deserial_addr = animstate_deserialize_sig.target_address;
        if (deserial_addr == 0 && setpos_sig.target_address != 0) {
            deserial_addr = setpos_sig.target_address + 0x10120;
        }
        if (deserial_addr != 0) {
            g_local_a0_patch_addr = deserial_addr + 0x45;
            g_local_a0_listener = gum_make_call_listener(
                &local_a0_on_enter, nullptr, nullptr, nullptr);
            auto r = gum_interceptor_attach(interceptor,
                reinterpret_cast<void *>(g_local_a0_patch_addr),
                g_local_a0_listener, nullptr);
            if (r == GUM_ATTACH_OK) {
                debug_log("[install] local_a0 patch at 0x%llx\n",
                          static_cast<unsigned long long>(g_local_a0_patch_addr));
                std::fprintf(stderr, "[JitterProbe] local_a0 patch at %p\n",
                             reinterpret_cast<void *>(g_local_a0_patch_addr));
            } else {
                debug_log("[install] local_a0 attach failed: %d\n", static_cast<int>(r));
            }
        }
    }
    // AnimState Deserialize — preserve flAnimTime for local player.
    // Primary: signature scan. Fallback: compute from SetPosition address (constant offset 0x10120).
    if (!install_one(interceptor, animstate_deserialize_sig,
                     reinterpret_cast<void *>(&hooked_AnimStateDeserialize),
                     reinterpret_cast<void **>(&original_AnimStateDeserialize),
                     "AnimStateDeserialize")) {
        std::fprintf(stderr, "[JitterProbe] AnimStateDeserialize sig scan failed, trying fallback\n");
        debug_log("[install] AnimStateDeserialize sig failed, trying SetPosition+0x10120 fallback\n");
        // Fallback: SetPosition and AnimStateDeserialize have a constant offset of 0x10120.
        if (setpos_sig.target_address != 0) {
            uintptr_t anim_addr = setpos_sig.target_address + 0x10120;
            debug_log("[install] fallback addr=0x%llx (SetPosition=0x%llx)\n",
                      static_cast<unsigned long long>(anim_addr),
                      static_cast<unsigned long long>(setpos_sig.target_address));
            auto r = gum_interceptor_replace(
                interceptor,
                reinterpret_cast<void *>(anim_addr),
                reinterpret_cast<void *>(&hooked_AnimStateDeserialize),
                reinterpret_cast<void **>(&original_AnimStateDeserialize),
                nullptr);
            if (r == GUM_REPLACE_OK) {
                debug_log("[install] FALLBACK HOOKED: AnimStateDeserialize at 0x%llx\n",
                          static_cast<unsigned long long>(anim_addr));
                std::fprintf(stderr, "[JitterProbe] hooked AnimStateDeserialize (fallback) at %p\n",
                             reinterpret_cast<void *>(anim_addr));
            } else {
                debug_log("[install] FALLBACK REPLACE FAILED: rc=%d\n", static_cast<int>(r));
                std::fprintf(stderr, "[JitterProbe] AnimStateDeserialize fallback failed: %d\n",
                             static_cast<int>(r));
            }
        } else {
            debug_log("[install] SetPosition target_address is 0, cannot fallback\n");
        }
    }
    return ok;
}

static void flush_ring_unlocked(const char *reason) {
    const uint64_t seq = g_seq.load(std::memory_order_relaxed);
    const uint32_t head = g_head.load(std::memory_order_relaxed);
    const uint32_t n = static_cast<uint32_t>(seq > kRing ? kRing : seq);

    // One-line summary to stderr only (never dump thousands of lines to game log).
    std::fprintf(stderr,
                 "[JitterProbe] flush reason=%s seq=%llu seen=%llu track=%llx "
                 "local_only=%d events=%u -> file\n",
                 reason,
                 static_cast<unsigned long long>(seq),
                 static_cast<unsigned long long>(g_seen.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(g_track_self.load(std::memory_order_relaxed)),
                 g_local_only.load(std::memory_order_relaxed) ? 1 : 0,
                 n);

    // Unique dump path so game/jit runs do not overwrite each other.
    //   data/unsafedata/jitter_probe_dump_<vm>_<YYYYMMDD_HHMMSS>.txt
    // Plus jitter_probe_dump_latest.txt in the same directory.
    const char *vm = "run";
    {
        std::lock_guard lock(g_vm_tag_mu);
        if (g_vm_tag_buf[0] != '\0') {
            vm = g_vm_tag_buf;
        }
    }
    if (const char *env = std::getenv("JITTER_PROBE_VM_TAG")) {
        if (env[0] != '\0') {
            vm = env;
        }
    }
    char vm_tag[32] = {};
    {
        size_t j = 0;
        for (size_t i = 0; vm[i] != '\0' && j + 1 < sizeof(vm_tag); ++i) {
            const char c = vm[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-') {
                vm_tag[j++] = c;
            }
        }
        if (j == 0) {
            vm_tag[0] = 'r';
            vm_tag[1] = 'u';
            vm_tag[2] = 'n';
            vm_tag[3] = '\0';
        }
    }

    std::time_t now = std::time(nullptr);
    std::tm tm_buf{};
#ifdef _WIN32
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    char ts[32] = {};
    std::strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm_buf);

    const char *dirs[] = {"data/unsafedata/", "unsafedata/", ""};
    FILE *f = nullptr;
    char primary_path[280] = {};
    char latest_path[280] = {};
    for (const char *dir : dirs) {
        std::snprintf(primary_path, sizeof(primary_path),
                      "%sjitter_probe_dump_%s_%s.txt", dir, vm_tag, ts);
        f = std::fopen(primary_path, "w");
        if (f) {
            std::snprintf(latest_path, sizeof(latest_path),
                          "%sjitter_probe_dump_latest.txt", dir);
            std::fprintf(stderr, "[JitterProbe] writing %s\n", primary_path);
            break;
        }
        primary_path[0] = '\0';
    }
    if (!f) {
        std::fprintf(stderr, "[JitterProbe] could not open dump file\n");
        return;
    }
    std::fprintf(f,
                 "# reason=%s seq=%llu seen=%llu track=%llx local_only=%d n=%u vm=%s ts=%s\n"
                 "# ops: SetPos Teleport Deserialize DeserializePost EnablePred "
                 "FrameBegin(x=dt_s) FrameEnd(x=wall_ms,y=cache_ms,z=draw_ms) "
                 "CacheRender(x=ms,y=0begin/1end) DrawCache(x=ms,y=0begin/1end)\n",
                 reason,
                 static_cast<unsigned long long>(seq),
                 static_cast<unsigned long long>(g_seen.load(std::memory_order_relaxed)),
                 static_cast<unsigned long long>(g_track_self.load(std::memory_order_relaxed)),
                 g_local_only.load(std::memory_order_relaxed) ? 1 : 0, n,
                 vm_tag, ts);
    if (n == 0) {
        std::fclose(f);
    } else {
        const uint32_t start = (head + kRing - n) % kRing;
        for (uint32_t i = 0; i < n; ++i) {
            const Event &e = g_ring[(start + i) % kRing];
            std::fprintf(f,
                         "%llu %s %llx %.5f %.5f %.5f %.5f %.5f %.5f %d %u %u\n",
                         static_cast<unsigned long long>(e.t_ns),
                         op_name(e.op),
                         static_cast<unsigned long long>(e.self),
                         e.x, e.y, e.z, e.ox, e.oy, e.oz,
                         static_cast<int>(e.pred),
                         static_cast<unsigned>(e.respect),
                         static_cast<unsigned>(e.flags));
        }
        std::fclose(f);
    }

    // Convenience alias for "last flush" without losing the unique primary.
    if (primary_path[0] != '\0' && latest_path[0] != '\0') {
        if (std::FILE *src = std::fopen(primary_path, "rb")) {
            if (std::FILE *dst = std::fopen(latest_path, "wb")) {
                char buf[8192];
                size_t nread = 0;
                while ((nread = std::fread(buf, 1, sizeof(buf), src)) > 0) {
                    std::fwrite(buf, 1, nread, dst);
                }
                std::fclose(dst);
                std::fprintf(stderr, "[JitterProbe] also %s\n", latest_path);
            }
            std::fclose(src);
        }
    }
}

} // namespace

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_enable(bool enable) {
    if (enable && !g_hooks_installed.load(std::memory_order_acquire)) {
        if (install_hooks()) {
            g_hooks_installed.store(true, std::memory_order_release);
        } else {
            std::fprintf(stderr, "[JitterProbe] hook install incomplete — probe partial\n");
            g_hooks_installed.store(true, std::memory_order_release);
        }
    }
    g_enabled.store(enable, std::memory_order_release);
    std::fprintf(stderr, "[JitterProbe] enabled=%d (ring=%zu local_only=%d)\n",
                 enable ? 1 : 0, kRing,
                 g_local_only.load(std::memory_order_relaxed) ? 1 : 0);
    if (!enable) {
        std::lock_guard lock(g_flush_mu);
        flush_ring_unlocked("disable");
    }
}

DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_jitter_probe_is_enabled() {
    return g_enabled.load(std::memory_order_acquire);
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_track(void *transform) {
    g_track_self.store(reinterpret_cast<uint64_t>(transform), std::memory_order_release);
    std::fprintf(stderr, "[JitterProbe] track_self=%p\n", transform);
}

// Resolve cTransformComponent* from cEntity* (Win x64).
// Preferred: entity+0xF0 (lag-comp table). Sanity: transform+0x18 back-ref == entity.
// Fallback: entity+0x1E0 adjustor-style (-0x20) used by entity::EnableMovementPrediction.
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_track_entity(void *entity) {
    if (!entity) {
        g_track_self.store(0, std::memory_order_release);
        std::fprintf(stderr, "[JitterProbe] track_entity=null -> track cleared\n");
        return;
    }
    auto *ent = static_cast<char *>(entity);
    void *candidates[2] = {
        *reinterpret_cast<void **>(ent + 0xF0),
        nullptr,
    };
    void *slot_1e0 = *reinterpret_cast<void **>(ent + 0x1E0);
    if (slot_1e0) {
        candidates[1] = static_cast<char *>(slot_1e0) - 0x20;
    }
    void *chosen = nullptr;
    for (void *cand : candidates) {
        if (!cand) {
            continue;
        }
        void *back = *reinterpret_cast<void **>(static_cast<char *>(cand) + 0x18);
        if (back == entity) {
            chosen = cand;
            break;
        }
        if (!chosen) {
            chosen = cand; // keep first non-null as weak fallback
        }
    }
    g_track_self.store(reinterpret_cast<uint64_t>(chosen), std::memory_order_release);
    std::fprintf(stderr,
                 "[JitterProbe] track_entity=%p transform=%p (f0=%p 1e0-20=%p back_ok=%d)\n",
                 entity, chosen, candidates[0], candidates[1],
                 (chosen && *reinterpret_cast<void **>(static_cast<char *>(chosen) + 0x18) == entity) ? 1
                                                                                                      : 0);
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_local_player_entity(void *entity) {
    g_local_player_entity.store(reinterpret_cast<uint64_t>(entity), std::memory_order_release);
    std::fprintf(stderr, "[JitterProbe] local_player_entity=%p\n", entity);
}

// Lua 5.1 compatible: return int (no pointer/FFI out-params).
// 0=not installed, 1=installed
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_hook_status() {
    return original_AnimStateDeserialize ? 1 : 0;
}
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_call_count() {
    return static_cast<int>(g_anim_deserialize_calls.load(std::memory_order_relaxed));
}
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_match_count() {
    return static_cast<int>(g_anim_entity_matches.load(std::memory_order_relaxed));
}
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_preserve_count() {
    return static_cast<int>(g_anim_time_preserved.load(std::memory_order_relaxed));
}
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_local_a0_patched() {
    return g_local_a0_patch_addr != 0 ? 1 : 0;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_local_only(bool on) {
    g_local_only.store(on, std::memory_order_release);
    std::fprintf(stderr, "[JitterProbe] local_only=%d\n", on ? 1 : 0);
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_flush() {
    std::lock_guard lock(g_flush_mu);
    flush_ring_unlocked("manual");
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_vm_tag(const char *tag) {
    std::lock_guard lock(g_vm_tag_mu);
    if (!tag || !tag[0]) {
        std::snprintf(g_vm_tag_buf, sizeof(g_vm_tag_buf), "run");
    } else {
        size_t j = 0;
        for (size_t i = 0; tag[i] != '\0' && j + 1 < sizeof(g_vm_tag_buf); ++i) {
            const char c = tag[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '-') {
                g_vm_tag_buf[j++] = c;
            }
        }
        g_vm_tag_buf[j] = '\0';
        if (j == 0) {
            std::snprintf(g_vm_tag_buf, sizeof(g_vm_tag_buf), "run");
        }
    }
    std::fprintf(stderr, "[JitterProbe] vm_tag=%s\n", g_vm_tag_buf);
}

#else // !_WIN32

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_enable(bool) {}
DONTSTARVEINJECTOR_GAME_API bool DS_LUAJIT_jitter_probe_is_enabled() { return false; }
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_track(void *) {}
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_local_only(bool) {}
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_flush() {}
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_vm_tag(const char *) {}
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_perframe_calls() { return 0; }
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_perframe_blocked() { return 0; }
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_track_entity(void *) {}
DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_jitter_probe_set_local_player_entity(void *) {}
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_hook_status() { return 0; }
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_call_count() { return 0; }
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_match_count() { return 0; }
DONTSTARVEINJECTOR_GAME_API int DS_LUAJIT_jitter_probe_get_anim_preserve_count() { return 0; }

#endif
