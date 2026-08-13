// ClientAnimHooks.cpp — pred-OFF local anim ownership (Win x64).
//
// Deserialize+0x47: set BL=1 for the local player only (skip PlayMode/AnimHash/AnimTime).
// Hardware write-watch on +0x28 remains so deser_time (0x9FE5E) would still show if
// the gate fails. Loop wrap (FUN_140098860) is render-seamless (GetFrame fmods).

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
#include <Windows.h>

namespace {

static function_relocation::MemorySignature animstate_deserialize_sig{
    "48 8B C4 "
    "56 "
    "57 "
    "48 81 EC B8 00 00 00 "
    "83 3A 00 "
    "48 8B FA "
    "48 8B F1",
    0};

static constexpr int ASC_ENTITY = 0x18;
static constexpr int ASC_FL_ANIM_TIME = 0x28;
static constexpr std::size_t kLocalA0TailOff = 0x41;
static constexpr unsigned char kLocalA0TailExpected[] = {
    0xB3, 0x01, 0xEB, 0x02, 0x32, 0xDB, 0x48, 0x8B, 0xCF,
};
static constexpr std::size_t kAttachInsnOff = 0x47; // MOV RCX,RDI
static std::atomic_bool g_own{false};
static std::atomic_uint64_t g_local_player_entity{0};
static std::atomic_uint64_t g_enter_count{0};
static std::atomic_uint64_t g_match_count{0};
static uintptr_t g_attach_addr = 0;
static GumInvocationListener *g_listener = nullptr;
static bool g_installed = false;
static bool g_xor_patched = false;

static std::atomic_uint64_t g_watch_addr{0};
static std::atomic_uint32_t g_watch_hits{0};
static std::atomic_uint32_t g_watch_writes{0};
static std::atomic<float> g_last_time{0.f};
static char g_watch_last[256] = "none";
static guint64 g_mod_base = 0;
static gsize g_mod_size = 0;
static bool g_exceptor_on = false;
static bool g_watch_armed = false;

static void fmt_mod(char *out, size_t n, guint64 addr) {
    if (g_mod_size != 0 && addr >= g_mod_base && addr < g_mod_base + g_mod_size) {
        std::snprintf(out, n, "exe+0x%llX",
                      static_cast<unsigned long long>(addr - g_mod_base));
    } else {
        std::snprintf(out, n, "0x%llX", static_cast<unsigned long long>(addr));
    }
}

static const char *classify_rva(guint64 rva) {
    // FUN_14009fc60 stores to flAnimTime; SINGLE_STEP RIP is often the next insn.
    if (rva == 0x9FDD6 || rva == 0x9FDDA) return "deser_zero";
    if (rva == 0x9FE5E || rva == 0x9FE63) return "deser_time";
    return "";
}

static gboolean on_watch_exception(GumExceptionDetails *details, gpointer) {
    if (!details || details->type != GUM_EXCEPTION_SINGLE_STEP) {
        return FALSE;
    }
    const uint64_t watched = g_watch_addr.load(std::memory_order_relaxed);
    if (watched == 0) {
        return FALSE;
    }
    auto *winctx = static_cast<CONTEXT *>(details->native_context);
    if (winctx && (winctx->Dr6 & 1u) == 0) {
        return FALSE;
    }

    const float now = *reinterpret_cast<const float *>(watched);
    const float prev = g_last_time.load(std::memory_order_relaxed);
    g_last_time.store(now, std::memory_order_relaxed);
    g_watch_writes.fetch_add(1, std::memory_order_relaxed);

    const float delta = now - prev;
    const bool rewind = (prev - now) > 0.2f;
    const bool unusual = !rewind && !(delta >= 0.f && delta <= 0.05f);
    if (!rewind && !(unusual && g_watch_hits.load(std::memory_order_relaxed) < 8)) {
        return TRUE;
    }

    const guint64 ea = reinterpret_cast<guint64>(details->address);
    const guint64 crip = winctx ? static_cast<guint64>(winctx->Rip) : 0;
    char ea_s[32], rip_s[32], r0[32], r1[32];
    fmt_mod(ea_s, sizeof(ea_s), ea);
    fmt_mod(rip_s, sizeof(rip_s), crip);
    const guint64 *rsp = winctx ? reinterpret_cast<const guint64 *>(winctx->Rsp) : nullptr;
    fmt_mod(r0, sizeof(r0), rsp ? rsp[0] : 0);
    fmt_mod(r1, sizeof(r1), rsp ? rsp[1] : 0);

    const guint64 rva = (g_mod_size && ea >= g_mod_base && ea < g_mod_base + g_mod_size)
                            ? (ea - g_mod_base)
                            : (g_mod_size && crip >= g_mod_base && crip < g_mod_base + g_mod_size
                                   ? (crip - g_mod_base)
                                   : 0);
    const char *tag = classify_rva(rva);
    if (!tag[0] && g_mod_size && crip >= g_mod_base) {
        tag = classify_rva(crip - g_mod_base);
    }

    const unsigned hit = g_watch_hits.fetch_add(1, std::memory_order_relaxed) + 1;
    std::snprintf(g_watch_last, sizeof(g_watch_last),
                  "hit=%u %s %.4f<-%.4f ea=%s rip=%s %s ret=%s,%s",
                  hit, rewind ? "REWIND" : "write", now, prev, ea_s, rip_s, tag, r0, r1);
    std::fprintf(stderr, "[client.anim] watch %s\n", g_watch_last);
    return TRUE;
}

static gboolean set_wp_on_thread(const GumThreadDetails *td, gpointer user_data) {
    const auto addr = *static_cast<GumAddress *>(user_data);
    GError *err = nullptr;
    gum_thread_set_hardware_watchpoint(td->id, 0, addr, 4, GUM_WATCH_WRITE, &err);
    if (err) {
        std::fprintf(stderr, "[client.anim] watch tid=%u fail: %s\n",
                     static_cast<unsigned>(td->id), err->message);
        g_error_free(err);
    }
    return TRUE;
}

static std::atomic_bool g_arming{false};
static GumAddress g_arm_addr = 0;

static DWORD WINAPI arm_watch_thread(LPVOID) {
    GumAddress addr = g_arm_addr;
    gum_process_enumerate_threads(&set_wp_on_thread, &addr, GUM_THREAD_FLAGS_NONE);
    g_watch_armed = true;
    std::fprintf(stderr, "[client.anim] watch armed flAnimTime=%p exe_base=%p\n",
                 reinterpret_cast<void *>(addr),
                 reinterpret_cast<void *>(g_mod_base));
    return 0;
}

static void arm_watch(char *anim) {
    const uint64_t addr =
        reinterpret_cast<uint64_t>(anim + ASC_FL_ANIM_TIME);
    const uint64_t prev = g_watch_addr.load(std::memory_order_relaxed);
    if ((prev == addr && g_watch_armed) || g_arming.load(std::memory_order_relaxed)) {
        return;
    }
    g_watch_addr.store(addr, std::memory_order_release);
    g_last_time.store(*reinterpret_cast<float *>(addr), std::memory_order_relaxed);

    if (!g_exceptor_on) {
        GumExceptor *ex = gum_exceptor_obtain();
        if (ex) {
            gum_exceptor_add(ex, &on_watch_exception, nullptr);
            g_exceptor_on = true;
        }
    }
    if (g_mod_base == 0) {
        GumModule *mod = gum_process_get_main_module();
        if (mod) {
            const GumMemoryRange *r = gum_module_get_range(mod);
            if (r) {
                g_mod_base = r->base_address;
                g_mod_size = r->size;
            }
        }
    }

    // __writedr is ring-0; SetThreadContext(self) is unreliable inside a hook.
    // Apply Dr0 from a helper thread via gum_thread_set_hardware_watchpoint.
    g_arm_addr = addr;
    g_arming.store(true, std::memory_order_release);
    HANDLE th = CreateThread(nullptr, 0, &arm_watch_thread, nullptr, 0, nullptr);
    if (th) {
        CloseHandle(th);
    } else {
        g_arming.store(false, std::memory_order_release);
        std::fprintf(stderr, "[client.anim] watch helper thread failed err=%lu\n",
                     GetLastError());
    }
}

static void on_enter(GumInvocationContext *context, gpointer) {
    g_enter_count.fetch_add(1, std::memory_order_relaxed);
    if (!g_own.load(std::memory_order_relaxed)) return;
    if (!context || !context->cpu_context) return;
    auto *cpu = context->cpu_context;
    auto *anim = reinterpret_cast<char *>(cpu->rsi);
    if (!anim) return;
    void *entity = *reinterpret_cast<void **>(anim + ASC_ENTITY);
    const uint64_t local = g_local_player_entity.load(std::memory_order_relaxed);
    if (local != 0 && reinterpret_cast<uint64_t>(entity) == local) {
        g_match_count.fetch_add(1, std::memory_order_relaxed);
        cpu->rbx |= 1;
        arm_watch(anim);
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

    // Do not rewrite XOR BL,BL — that forced local_a0 for every entity.
    // Local player only: on_enter sets cpu->rbx |= 1 after entity match.

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
                 "[client.anim] local_a0 attach at %p xor_patched=%d\n",
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

int client_anim_watch_armed() {
    return g_watch_armed ? 1 : 0;
}

int client_anim_watch_hits() {
    return static_cast<int>(g_watch_hits.load(std::memory_order_relaxed));
}

int client_anim_watch_writes() {
    return static_cast<int>(g_watch_writes.load(std::memory_order_relaxed));
}

const char *client_anim_watch_last() {
    return g_watch_last;
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
int client_anim_watch_armed() { return 0; }
int client_anim_watch_hits() { return 0; }
int client_anim_watch_writes() { return 0; }
const char *client_anim_watch_last() { return "n/a"; }

#endif
