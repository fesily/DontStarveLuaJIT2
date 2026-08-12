// ClientAnimHooks.cpp — pred-OFF local anim ownership (Win x64).
//
// When Lua sets own=true for the local player, force cAnimStateComponent::Deserialize
// local_a0=true (skip PlayMode/AnimHash/AnimTime) so network does not stomp local
// run/idle. Position remains server-authoritative (no EnableMovementPrediction).
//
// Attach AFTER XOR BL,BL (function+0x47). Gum re-executes the hooked insn in
// on_invoke_trampoline; attaching on XOR itself would clear BL again.

#include "ClientAnimHooks.hpp"
#include "MemorySignature.hpp"
#include "ctx.hpp"
#include "config/InjectorHostConfig.hpp"

#include <atomic>
#include <cstdint>
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

static std::atomic_bool g_own{false};
static std::atomic_uint64_t g_local_player_entity{0};
static std::atomic_uint64_t g_enter_count{0};
static std::atomic_uint64_t g_match_count{0};
static uintptr_t g_attach_addr = 0;
static GumInvocationListener *g_listener = nullptr;
static bool g_installed = false;

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
        cpu->rbx |= 1; // BL=1 → skip PlayMode/AnimHash/AnimTime
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
    // Layout: +0x41 MOV BL,1; +0x43 JMP +2; +0x45 XOR BL,BL; +0x47 MOV RCX,RDI (merge).
    g_attach_addr = deserial_addr + 0x47;
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
    std::fprintf(stderr, "[client.anim] local_a0 attach at %p (Deserialize+0x47)\n",
                 reinterpret_cast<void *>(g_attach_addr));
    return true;
}

void client_anim_set_local_player_entity(void *entity) {
    g_local_player_entity.store(reinterpret_cast<uint64_t>(entity), std::memory_order_release);
    std::fprintf(stderr, "[client.anim] local_player_entity=%p\n", entity);
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

#else // !_WIN32

bool client_anim_install_hooks() { return false; }
void client_anim_set_local_player_entity(void *) {}
void client_anim_set_own(bool) {}
bool client_anim_get_own() { return false; }
bool client_anim_is_installed() { return false; }
int client_anim_enter_count() { return 0; }
int client_anim_match_count() { return 0; }

#endif
