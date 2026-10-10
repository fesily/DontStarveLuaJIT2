// ClientPingHook.cpp — per-client RTT probe for network.stats.
//
// Strategy
//   * Anchor cNetworkClientObject2::UpdateNetStats by byte signature (never by
//     a fixed address), then derive all offsets with ClientPingDecode.
//   * Attach one invocation listener: on_enter binds the call to a client table
//     row by reading the client's userid (cPlayerListingData string), on_leave
//     reads the engine's own stats ring. The ring's newest slot is exactly the
//     RTT the engine resolved through the peer this tick (both measured
//     platforms store the clamped query result there), so the probe is a pure
//     read-only observer — no engine function is replaced or called.
//   * The only value kept per client is that RTT, keyed by userid.
//
// Fail closed at every step: anchor miss / decode failure / attach failure =>
// feature disabled, the export answers -1, engine behaviour untouched.

#include "ClientPingHook.hpp"

#include "ClientPingDecode.hpp"

#include "config/InjectorHostConfig.hpp"
#include "util/frida_gum_interceptor.hpp"

#include "MemorySignature.hpp"
#include "ctx.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

#if defined(_M_X64) || defined(__x86_64__)

namespace ds::net_stats {

namespace {

// ---------------------------------------------------------------------------
// Anchor signatures. Signature-first rule: never hardcode an image RVA.
// Verified shapes (2026-10, both binaries scanned; total hits must be exactly 1):
//   Windows x64  dontstarve_steam_x64.exe and
//                dontstarve_dedicated_server_nullrenderer_x64.exe
//                — the same literal covers both Windows binaries.
//   Linux x64    dontstarve_dedicated_server_nullrenderer_x64.
// Multiple literals per platform are allowed; the combined hit count must be 1.
// ---------------------------------------------------------------------------
#if defined(_WIN32)
constexpr const char *kAnchorPatterns[] = {
    // mov r11,rsp; push rbx; push rsi; sub rsp,imm32; mov rax,[rip+d];
    // mov rbx,rcx; mov rsi,[rax+2B0h]; test rsi,rsi
    "4C 8B DC 53 56 48 81 EC ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8B D9 48 8B B0 B0 02 00 00 48 85 F6",
};
#elif defined(__linux__)
constexpr const char *kAnchorPatterns[] = {
    // push r14; push r13; push r12; push rbp; push rbx; sub rsp,140h;
    // mov rax,fs:[28h]; mov [rsp+138h],rax; xor eax,eax; mov rax,[rip+d];
    // mov rbp,[rax+1A0h]; test rbp,rbp
    "41 56 41 55 41 54 55 53 48 81 EC 40 01 00 00 64 48 8B 04 25 28 00 00 00 48 89 84 24 38 01 00 00 31 C0 48 8B 05 ?? ?? ?? ?? 48 8B A8 A0 01 00 00 48 85 ED",
};
#else
constexpr const char *kAnchorPatterns[] = {nullptr}; // deferred platform
#endif

constexpr int32_t kPingClampMax = 99999; // engine clamp constant (invalid marker)

struct ClientEntry {
    char    userid[64]{};
    int32_t ping_ms = -1;
    bool    used = false;
    bool    announced = false; // evidence line emitted for this entry
};

struct State {
    bool installed = false;
    std::atomic<bool> disabled{true};
    uintptr_t anchor = 0;
    NetStatsLayout layout{};
};

State g_state;
std::mutex g_mu; // guards the client table + install-time meta fields

ClientEntry g_entries[kClientPingMaxClients];
std::string g_reason;
bool g_table_full_reported = false;
bool g_userid_failure_reported = false;

ClientEntry *find_by_userid_locked(const char *userid) {
    for (auto &e : g_entries) {
        if (e.used && std::strcmp(e.userid, userid) == 0) {
            return &e;
        }
    }
    return nullptr;
}

ClientEntry *upsert_locked(const char *userid) {
    if (ClientEntry *e = find_by_userid_locked(userid)) {
        return e;
    }
    for (auto &e : g_entries) {
        if (!e.used) {
            e = ClientEntry{};
            std::memcpy(e.userid, userid, sizeof(e.userid));
            e.used = true;
            return &e;
        }
    }
    if (!g_table_full_reported) {
        g_table_full_reported = true;
        std::fprintf(stderr, "[net.stats] client table full (%zu) — dropping new clients\n",
                     kClientPingMaxClients);
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// userid reading: cPlayerListingData starts with the userid std::string.
// Both STL layouts are tried; a candidate is only accepted when it passes the
// printable + NUL-terminated validation. Without a userid there is no key to
// publish under, so the tick is skipped.
// ---------------------------------------------------------------------------
bool validate_userid(const char *data, uint64_t len, char out[64]) {
    if (len == 0 || len > 63) {
        return false;
    }
    if (!gum_memory_is_readable(static_cast<gconstpointer>(data), static_cast<gsize>(len) + 1)) {
        return false;
    }
    for (uint64_t i = 0; i < len; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    if (data[len] != '\0') {
        return false;
    }
    std::memcpy(out, data, static_cast<size_t>(len));
    out[len] = '\0';
    return true;
}

bool try_read_msvc_string(const uint8_t *s, char out[64]) {
    // MSVC std::string (32B): { union { char buf[16]; char* ptr; }; size_t size; size_t capacity; }
    uint64_t size = 0;
    uint64_t cap = 0;
    std::memcpy(&size, s + 0x10, sizeof(size));
    std::memcpy(&cap, s + 0x18, sizeof(cap));
    if (cap >= 16) {
        char *data = nullptr;
        std::memcpy(&data, s, sizeof(data));
        return data && validate_userid(data, size, out);
    }
    return validate_userid(reinterpret_cast<const char *>(s), size, out);
}

bool try_read_libcpp_string(const uint8_t *s, char out[64]) {
    // libc++ std::string: byte0 bit0 = is_long; long: {char* data; size_t size;}
    if ((s[0] & 1) != 0) {
        char *data = nullptr;
        uint64_t size = 0;
        std::memcpy(&data, s, sizeof(data));
        std::memcpy(&size, s + 8, sizeof(size));
        return data && validate_userid(data, size, out);
    }
    const uint64_t size = static_cast<uint64_t>(s[0] >> 1);
    return validate_userid(reinterpret_cast<const char *>(s) + 1, size, out);
}

// The userid std::string sits at the listing base (engine: c_str(this+0x1c0)).
// The trusted self object was observed with the string object 8 bytes later, so
// both offsets are probed with both STL layouts; every candidate must pass the
// printable + NUL-terminated validation. The accepted shape is logged once.
bool try_read_userid(const uint8_t *listing, char out[64]) {
    struct Candidate {
        uint32_t off;
        bool msvc;
    };
    static const Candidate kCandidates[] = {{0, true}, {0, false}, {8, true}, {8, false}};
    for (const auto &cand : kCandidates) {
        const uint8_t *s = listing + cand.off;
        if (cand.msvc ? try_read_msvc_string(s, out) : try_read_libcpp_string(s, out)) {
            static std::atomic<bool> reported{false};
            if (!reported.exchange(true)) {
                std::fprintf(stderr, "[net.stats] userid layout: off=+%u %s\n", cand.off,
                             cand.msvc ? "msvc" : "libcpp");
            }
            return true;
        }
    }
    return false;
}

// One grep-able evidence line per client (first non-negative RTT).
void announce_locked(ClientEntry &e) {
    if (e.ping_ms < 0 || e.announced) {
        return;
    }
    e.announced = true;
    std::fprintf(stderr, "[net.stats] client=%s ping=%dms\n", e.userid, e.ping_ms);
}

// ---------------------------------------------------------------------------
// Hook callbacks (gum C-API listener; the InvocationListenerProxy helper in
// util/ is not usable with this gum version — GUM_INVOCATION_LISTENER does not
// exist there). The enter callback resolves the row and hands it to the leave
// callback through the invocation data, so no object identity is re-read.
// ---------------------------------------------------------------------------
struct InvocationSlot {
    gpointer obj = nullptr;
    ClientEntry *entry = nullptr;
};

void on_enter_cb(GumInvocationContext *ctx, gpointer) {
    auto *slot = static_cast<InvocationSlot *>(
        gum_invocation_context_get_listener_invocation_data(ctx, sizeof(InvocationSlot)));
    gpointer obj = gum_invocation_context_get_nth_argument(ctx, 0);
    if (slot) {
        slot->obj = obj;
        slot->entry = nullptr;
    }
    if (!slot || !obj || g_state.disabled.load(std::memory_order_relaxed)) {
        return;
    }

    char userid[64] = {};
    if (!try_read_userid(static_cast<const uint8_t *>(obj) + g_state.layout.listingOff, userid)) {
        if (!g_userid_failure_reported) {
            g_userid_failure_reported = true;
            std::fprintf(stderr, "[net.stats] userid read failed — client skipped until readable\n");
        }
        return;
    }

    std::lock_guard lock(g_mu);
    slot->entry = upsert_locked(userid);
}

void on_leave_cb(GumInvocationContext *ctx, gpointer) {
    auto *slot = static_cast<InvocationSlot *>(
        gum_invocation_context_get_listener_invocation_data(ctx, sizeof(InvocationSlot)));
    if (!slot || !slot->entry || g_state.disabled.load(std::memory_order_relaxed)) {
        return;
    }

    const auto &l = g_state.layout;
    const uint8_t *base = static_cast<const uint8_t *>(slot->obj);
    void *ring = nullptr;
    std::memcpy(&ring, base + l.ringPtrOff, sizeof(ring));
    if (!ring) {
        return;
    }
    const int8_t idx = *reinterpret_cast<const int8_t *>(base + l.indexOff);
    const uint32_t idx_u =
        (idx >= 0 && static_cast<uint32_t>(idx) < l.ringWindow) ? static_cast<uint32_t>(idx) : 0;

    uint32_t raw = 0;
    std::memcpy(&raw, static_cast<const uint8_t *>(ring) + static_cast<size_t>(idx_u) * l.ringStride,
                sizeof(raw));

    // The engine stores the clamped RTT query result in the newest slot; the
    // clamp sentinel means "no usable sample".
    std::lock_guard lock(g_mu);
    slot->entry->ping_ms = raw >= static_cast<uint32_t>(kPingClampMax) ? -1 : static_cast<int32_t>(raw);
    announce_locked(*slot->entry);
}

} // namespace

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------
bool install() {
    if (g_state.installed) {
        return !g_state.disabled.load();
    }
    g_state.installed = true;

    auto set_disabled = [](std::string reason) {
        {
            std::lock_guard lock(g_mu);
            g_reason = std::move(reason);
        }
        g_state.disabled.store(true);
    };

    if (kAnchorPatterns[0] == nullptr) {
        set_disabled("unsupported platform");
        return false;
    }

    if (!InjectorCtx::instance()) {
        set_disabled("injector context unavailable");
        return false;
    }

    size_t hits = 0;
    uintptr_t anchor = 0;
    const char *main_path = gum_module_get_path(gum_process_get_main_module());
    for (const char *pattern : kAnchorPatterns) {
        if (pattern == nullptr) {
            continue;
        }
        function_relocation::MemorySignature sig{pattern, 0};
        sig.only_one = false;
        sig.log = false;
        sig.prot_flag = GUM_PAGE_EXECUTE | GUM_PAGE_READ;
        if (main_path) {
            sig.scan(main_path);
        }
        hits += sig.targets.size();
        if (sig.targets.size() == 1 && anchor == 0) {
            anchor = sig.targets.front();
        }
    }
    if (hits != 1 || anchor == 0) {
        std::fprintf(stderr, "[net.stats] anchor miss (hits=%zu) — disabled\n", hits);
        spdlog::error("[net.stats] anchor miss (hits={}) — disabled", hits);
        set_disabled("anchor miss");
        return false;
    }

    const auto layout = decode_net_stats(anchor);
    if (!layout) {
        const std::string &reason = layout.error();
        std::fprintf(stderr, "[net.stats] decode failed (%s) at 0x%llx — disabled\n", reason.c_str(),
                     static_cast<unsigned long long>(anchor));
        spdlog::error("[net.stats] decode failed ({}) at 0x{:x} — disabled", reason, anchor);
        set_disabled("decode: " + reason);
        return false;
    }

    {
        std::lock_guard lock(g_mu);
        g_state.layout = *layout;
        g_state.anchor = anchor;
        g_reason.clear();
    }

    auto *interceptor = InjectorCtx::instance()->GetGumInterceptor();
    if (!interceptor) {
        set_disabled("gum interceptor unavailable");
        return false;
    }
    GumInvocationListener *listener = gum_make_call_listener(on_enter_cb, on_leave_cb, nullptr, nullptr);
    if (!listener) {
        set_disabled("listener allocation failed");
        return false;
    }
    const auto rc = ds::gum::attach(interceptor, reinterpret_cast<gpointer>(anchor), listener, nullptr);
    if (rc != GUM_ATTACH_OK) {
        std::fprintf(stderr, "[net.stats] attach failed (rc=%d) at 0x%llx — disabled\n",
                     static_cast<int>(rc), static_cast<unsigned long long>(anchor));
        spdlog::error("[net.stats] attach failed (rc={}) at 0x{:x} — disabled", static_cast<int>(rc),
                      anchor);
        set_disabled("attach failed");
        return false;
    }

    g_state.disabled.store(false);
    std::fprintf(stderr, "[net.stats] anchor=0x%llx listing=+0x%x ring=+0x%x/+0x%x n=%u stride=%u\n",
                 static_cast<unsigned long long>(anchor), layout->listingOff, layout->ringPtrOff,
                 layout->indexOff, layout->ringWindow, layout->ringStride);
    return true;
}

// ---------------------------------------------------------------------------
// Read-side API
// ---------------------------------------------------------------------------
int32_t client_ping_lookup(const char *userid) {
    if (!userid || userid[0] == '\0') {
        return -1;
    }
    std::lock_guard lock(g_mu);
    const ClientEntry *e = find_by_userid_locked(userid);
    return e ? e->ping_ms : -1;
}

} // namespace ds::net_stats

#else // !x86-64: link-compatible no-op face.

namespace ds::net_stats {

bool install() { return false; }
int32_t client_ping_lookup(const char *) { return -1; }

} // namespace ds::net_stats

#endif
