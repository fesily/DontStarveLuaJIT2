// ClientAnimHooks.cpp — pred-OFF local anim ownership (Win x64).
//
// DIAGNOSTIC: unconditionally rewrite Deserialize+0x45 XOR BL,BL → MOV BL,1
// so local_a0 is true for EVERY entity. Isolates "does BL=1 skip AnimTime?"
// from the entity-match / cpu_context writeback questions.
// Attach at +0x47 stays for enter/match counters only.

#include "ClientAnimHooks.hpp"
#include "MemorySignature.hpp"
#include "ctx.hpp"
#include "config/InjectorHostConfig.hpp"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <cstdio>

#include <frida-gum.h>

#ifdef _WIN32

namespace {

// cAnimStateComponent::Deserialize (Win x64)
static function_relocation::MemorySignature animstate_deserialize_sig{
    "48 8B C4 "
    "56 "
    "57 "
    "48 81 EC B8 00 00 00 "
    "83 3A 00 "
    "48 8B FA "
    "48 8B F1",
    0};

// Win x64 offsets (from dontstarve_steam_x64 disasm)
static constexpr int ASC_ENTITY = 0x18;
// local_a0 tail at Deserialize+0x41..+0x49:
//   B3 01        MOV BL,1
//   EB 02        JMP +2
//   32 DB        XOR BL,BL   ← patched to B3 01
//   48 8B CF     MOV RCX,RDI <-- attach site (counters)
static constexpr std::size_t kLocalA0TailOff = 0x41;
static constexpr unsigned char kLocalA0TailExpected[] = {
    0xB3, 0x01, 0xEB, 0x02, 0x32, 0xDB, 0x48, 0x8B, 0xCF,
};
static constexpr std::size_t kXorInsnOff = 0x45;
static constexpr unsigned char kMovBl1[] = {0xB3, 0x01};
static constexpr std::size_t kAttachInsnOff = 0x47; // within function

static std::atomic_bool g_own{false};
static std::atomic_uint64_t g_local_player_entity{0};
static std::atomic_uint64_t g_enter_count{0};
static std::atomic_uint64_t g_match_count{0};
static uintptr_t g_attach_addr = 0;
static GumInvocationListener *g_listener = nullptr;
static bool g_installed = false;
static bool g_xor_patched = false;

static void on_enter(GumInvocationContext *context, gpointer) {
    g_enter_count.fetch_add(1, std::memory_order_relaxed);
    if (!g_own.load(std::memory_order_relaxed)) return;
    if (!context || !context->cpu_context) return;
    auto *cpu = context->cpu_context;
    // At +0x47, RSI still holds cAnimStateComponent* (entry: MOV RSI,RCX).
    auto *anim = reinterpret_cast<char *>(cpu->rsi);
    if (!anim) return;
    void *entity = *reinterpret_cast<void **>(anim + ASC_ENTITY);
    const uint64_t local = g_local_player_entity.load(std::memory_order_relaxed);
    if (local != 0 && reinterpret_cast<uint64_t>(entity) == local) {
        g_match_count.fetch_add(1, std::memory_order_relaxed);
        cpu->rbx |= 1; // belt: BL=1 already from patched MOV
    }
}

} // namespace

bool client_anim_install_hooks() {
    if (g_installed) return g_attach_addr != 0;
    g_installed = true;

    auto *ctx = InjectorCtx::instance();
    if (!ctx) {
        std::fprintf(stderr, "[client.anim] InjectorCtx unavailable\n");
        return false;
    }
    auto *interceptor = ctx->GetGumInterceptor();
    if (!interceptor) {
        std::fprintf(stderr, "[client.anim] GumInterceptor unavailable\n");
        return false;
    }
    (void)function_relocation::init_ctx();

    animstate_deserialize_sig.only_one = true;
    animstate_deserialize_sig.log = true;
    uintptr_t deserial_addr = animstate_deserialize_sig.scan(nullptr);
    if (deserial_addr == 0) {
        std::fprintf(stderr, "[client.anim] AnimStateDeserialize signature not found\n");
        return false;
    }
    // Layout: +0x41 MOV BL,1; +0x43 JMP +2; +0x45 XOR BL,BL; +0x47 MOV RCX,RDI.
    const auto *tail = reinterpret_cast<const unsigned char *>(deserial_addr + kLocalA0TailOff);
    if (std::memcmp(tail, kLocalA0TailExpected, sizeof(kLocalA0TailExpected)) != 0) {
        std::fprintf(stderr,
                     "[client.anim] local_a0 site mismatch at Deserialize+0x41 "
                     "(fn=%p). got:",
                     reinterpret_cast<void *>(deserial_addr));
        for (std::size_t i = 0; i < sizeof(kLocalA0TailExpected); ++i) {
            std::fprintf(stderr, " %02X", tail[i]);
        }
        std::fprintf(stderr, " expected:");
        for (unsigned char b : kLocalA0TailExpected) {
            std::fprintf(stderr, " %02X", b);
        }
        std::fprintf(stderr, "\n");
        return false;
    }
    const auto *attach_bytes =
        reinterpret_cast<const unsigned char *>(deserial_addr + kAttachInsnOff);
    if (attach_bytes[0] != 0x48 || attach_bytes[1] != 0x8B || attach_bytes[2] != 0xCF) {
        std::fprintf(stderr,
                     "[client.anim] attach insn mismatch at +0x47: %02X %02X %02X "
                     "(want 48 8B CF)\n",
                     attach_bytes[0], attach_bytes[1], attach_bytes[2]);
        return false;
    }

    auto *xor_site = reinterpret_cast<guint8 *>(deserial_addr + kXorInsnOff);
    if (!gum_memory_write(xor_site, kMovBl1, sizeof(kMovBl1))) {
        std::fprintf(stderr, "[client.anim] XOR->MOV BL,1 write failed at %p\n",
                     xor_site);
        return false;
    }
    if (xor_site[0] != 0xB3 || xor_site[1] != 0x01) {
        std::fprintf(stderr,
                     "[client.anim] XOR->MOV BL,1 verify failed: %02X %02X\n",
                     xor_site[0], xor_site[1]);
        return false;
    }
    g_xor_patched = true;
    std::fprintf(stderr,
                 "[client.anim] DIAG: XOR BL,BL -> MOV BL,1 at %p "
                 "(ALL entities skip PlayMode/AnimHash/AnimTime)\n",
                 xor_site);

    g_attach_addr = deserial_addr + kAttachInsnOff;
    g_listener = gum_make_call_listener(&on_enter, nullptr, nullptr, nullptr);
    auto r = gum_interceptor_attach(interceptor,
                                    reinterpret_cast<void *>(g_attach_addr),
                                    g_listener, nullptr);
    if (r != GUM_ATTACH_OK) {
        std::fprintf(stderr, "[client.anim] attach failed rc=%d at %p\n",
                     static_cast<int>(r), reinterpret_cast<void *>(g_attach_addr));
        g_attach_addr = 0;
        return false;
    }
    std::fprintf(stderr,
                 "[client.anim] local_a0 attach at %p (Deserialize+0x47; "
                 "xor_patched=%d)\n",
                 reinterpret_cast<void *>(g_attach_addr),
                 g_xor_patched ? 1 : 0);
    return true;
}

void client_anim_set_local_player_entity(void *entity) {
    g_local_player_entity.store(reinterpret_cast<uint64_t>(entity), std::memory_order_release);
}

void client_anim_set_own(bool on) {
    g_own.store(on, std::memory_order_release);
}

bool client_anim_get_own() {
    return g_own.load(std::memory_order_relaxed);
}

bool client_anim_is_installed() {
    return g_attach_addr != 0;
}

int client_anim_enter_count() {
    return static_cast<int>(g_enter_count.load(std::memory_order_relaxed));
}

int client_anim_match_count() {
    return static_cast<int>(g_match_count.load(std::memory_order_relaxed));
}

int client_anim_xor_patched() {
    return g_xor_patched ? 1 : 0;
}

#else // !_WIN32

bool client_anim_install_hooks() { return false; }
void client_anim_set_local_player_entity(void *) {}
void client_anim_set_own(bool) {}
bool client_anim_get_own() { return false; }
bool client_anim_is_installed() { return false; }
int client_anim_enter_count() { return 0; }
int client_anim_match_count() { return 0; }
int client_anim_xor_patched() { return 0; }

#endif
