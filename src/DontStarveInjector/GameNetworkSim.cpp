// GameNetworkSim.cpp
// Outbound network simulation (delay / jitter / loss) via hooking
// ReliabilityLayer::SendBitStream.
//
// Architecture:
//   - No threads (G1): DS_LUAJIT_net_sim_update() must be called each game tick
//   - Deep-copy BitStream data buffer, not pointer (G2)
//   - Reentrancy guard g_sim.is_releasing (G3)
//   - Queue capped at 2048 entries (G4)
//   - Outbound hook only (G5)
//   - All implementation guarded by #ifdef _WIN32 (G7)
//   - Hook installation is triggered lazily from the Lua-side netsim entry path
//
// Ghidra analysis notes (Win x64 dontstarve_steam_x64.exe):
//   SendBitStream:        0x14040a820 (confirmed via Ghidra decompiler)
//   ~ReliabilityLayer:    0x1404079f0 (FUN_1404079f0) — confirmed via DS_MemoryPool.h
//                         xrefs, vtable reassignment, and MemoryPool::Clear pattern
//                         matching macOS reference at 0x001e30e0.

#include "config.hpp"
#include "GameLua.hpp"
#include "MemorySignature.hpp"
#include "GameNetwork.hpp"

#include <cstdint>
#include <cstring>
#include <chrono>
#include <random>
#include <vector>
#include <deque>
#include <unordered_set>
#include <algorithm>

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#ifdef _WIN32

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

// Minimal fake BitStream header matching RakNet x64 layout:
//   offset  0  : int32_t numberOfBitsUsed
//   offset  4  : int32_t numberOfBitsAllocated  (unused by us, set to same)
//   offset  8  : uint8_t* data                  (pointer, 8 bytes on x64)
// There are additional fields after offset 16 that we zero-init.
// The callee (original_SendBitStream) only reads numberOfBitsUsed and data.
struct FakeBitStream {
    int32_t  numberOfBitsUsed    = 0;
    int32_t  numberOfBitsAllocated = 0;
    uint8_t* data                = nullptr;
    // Pad to a reasonable size so any innocent field reads don't AV.
    // In practice the callee only reads the two fields above.
    uint8_t  _pad[64]            = {};
};

struct QueuedPacket {
    void*                this_ptr;       // ReliabilityLayer* (connection tracking)
    void*                socket_ptr;     // RakNetSocket2* — kept as opaque pointer
    std::vector<uint8_t> sys_addr;       // deep copy of SystemAddress (136 bytes)
    std::vector<uint8_t> bitstream_data; // deep copy of BitStream data buffer
    int32_t              bits_used;      // numberOfBitsUsed from original BitStream
    void*                rnr;            // RakNetRandom* — opaque
    uint64_t             current_time;   // CCTimeType (uint64_t)
    uint64_t             release_at_ms;  // steady_clock ms when packet should fire
};

// ---------------------------------------------------------------------------
// SendBitStream function pointer type
// Win x64 calling convention:
//   rcx  = ReliabilityLayer* this
//   rdx  = RakNetSocket2*
//   r8   = SystemAddress& (passed by ref, 136 bytes)
//   r9   = BitStream*
//   [rsp+0x28] = RakNetRandom*
//   [rsp+0x30] = CCTimeType (uint64_t)
// ---------------------------------------------------------------------------
using SendBitStream_t = void(__fastcall*)(
    void*     reliabilityLayer,   // rcx
    void*     socket,             // rdx
    void*     sysAddr,            // r8  (SystemAddress&)
    void*     bitStream,          // r9  (BitStream*)
    void*     rnr,                // stack [0x28]
    uint64_t  current_time        // stack [0x30]
);

// ReliabilityLayer destructor type (single-arg, takes this)
using ReliabilityLayerDtor_t = void(__fastcall*)(void* reliabilityLayer);

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static struct SimState {
    bool     enabled     = false;
    uint32_t delay_ms    = 0;
    uint32_t jitter_ms   = 0;
    uint32_t loss_pct    = 0;   // 0-100

    // Counters (reset on disable)
    uint64_t packets_total    = 0;
    uint64_t packets_delayed  = 0;
    uint64_t packets_dropped  = 0;
    uint64_t packets_released = 0;

    // Reentrancy guard: set while we are calling original_SendBitStream
    // from the update/flush path, so the hook itself is not re-entered.
    bool is_releasing = false;

    std::mt19937_64 rng{ std::random_device{}() };
} g_sim;

static std::deque<QueuedPacket>          g_queue;
static std::unordered_set<void*>         g_alive_instances;
static bool                              g_hooks_installed = false;
static NetSimStats                       g_stats_cache{};

static SendBitStream_t         original_SendBitStream   = nullptr;
static ReliabilityLayerDtor_t  original_ReliabilityLayerDtor = nullptr;

void GameNetworkSimInstallHook(GumInterceptor* interceptor);

// ---------------------------------------------------------------------------
// Utility: monotonic millisecond timestamp
// ---------------------------------------------------------------------------
static uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count()
    );
}

// ---------------------------------------------------------------------------
// Flush a single queued packet — reconstructs fake BitStream and calls original.
// Caller must set g_sim.is_releasing = true before calling, and restore after.
// ---------------------------------------------------------------------------
static void flush_packet(const QueuedPacket& pkt) {
    if (g_alive_instances.count(pkt.this_ptr) == 0) {
        // Connection already destroyed — skip to avoid UAF
        return;
    }

    // Reconstruct a minimal fake BitStream on the stack
    FakeBitStream fbs;
    fbs.numberOfBitsUsed     = pkt.bits_used;
    fbs.numberOfBitsAllocated = pkt.bits_used;
    fbs.data = const_cast<uint8_t*>(pkt.bitstream_data.data());

    // Reconstruct SystemAddress: copy raw bytes into local buffer, pass by ptr
    std::vector<uint8_t> sys_addr_local(pkt.sys_addr);

    original_SendBitStream(
        pkt.this_ptr,
        pkt.socket_ptr,
        static_cast<void*>(sys_addr_local.data()),
        static_cast<void*>(&fbs),
        pkt.rnr,
        pkt.current_time
    );

    ++g_sim.packets_released;
}

// ---------------------------------------------------------------------------
// Hook: ReliabilityLayer destructor — lifecycle tracking
// ---------------------------------------------------------------------------
static void __fastcall hooked_ReliabilityLayerDtor(void* self) {
    g_alive_instances.erase(self);
    // Purge queued packets for this instance to avoid stale-ptr access
    g_queue.erase(
        std::remove_if(g_queue.begin(), g_queue.end(),
            [self](const QueuedPacket& p) { return p.this_ptr == self; }),
        g_queue.end());
    if (original_ReliabilityLayerDtor) {
        original_ReliabilityLayerDtor(self);
    }
}

// ---------------------------------------------------------------------------
// Hook: ReliabilityLayer::SendBitStream
// ---------------------------------------------------------------------------
static void __fastcall hooked_SendBitStream(
    void*    self,
    void*    socket,
    void*    sysAddr,
    void*    bitStream,
    void*    rnr,
    uint64_t current_time)
{
    // G3: passthrough immediately if sim disabled or we are already releasing
    if (!g_sim.enabled || g_sim.is_releasing) {
        original_SendBitStream(self, socket, sysAddr, bitStream, rnr, current_time);
        return;
    }

    // MH7: track this connection
    g_alive_instances.insert(self);

    // Count total outbound packets
    ++g_sim.packets_total;

    // Loss check
    if (g_sim.loss_pct > 0) {
        std::uniform_int_distribution<int> loss_dist(0, 99);
        if (loss_dist(g_sim.rng) < static_cast<int>(g_sim.loss_pct)) {
            ++g_sim.packets_dropped;
            return; // drop the packet
        }
    }

    // If no delay configured, send immediately (pass-through)
    if (g_sim.delay_ms == 0 && g_sim.jitter_ms == 0) {
        original_SendBitStream(self, socket, sysAddr, bitStream, rnr, current_time);
        return;
    }

    // Deep-copy BitStream data buffer (G2)
    const int32_t bits_used = *reinterpret_cast<const int32_t*>(bitStream);
    const uint8_t* src_data = *reinterpret_cast<const uint8_t* const*>(reinterpret_cast<const uint8_t*>(bitStream) + 8);
    const int byte_count    = (bits_used + 7) / 8;

    std::vector<uint8_t> bs_copy;
    if (byte_count > 0 && src_data != nullptr) {
        bs_copy.resize(static_cast<size_t>(byte_count));
        std::memcpy(bs_copy.data(), src_data, static_cast<size_t>(byte_count));
    }

    // Deep-copy SystemAddress (136 bytes)
    std::vector<uint8_t> sa_copy(136);
    if (sysAddr != nullptr) {
        std::memcpy(sa_copy.data(), sysAddr, 136);
    }

    // Calculate release time with jitter
    const uint64_t base_delay = static_cast<uint64_t>(g_sim.delay_ms);
    uint64_t total_delay = base_delay;
    if (g_sim.jitter_ms > 0) {
        std::uniform_int_distribution<int64_t> jitter_dist(
            -static_cast<int64_t>(g_sim.jitter_ms),
            static_cast<int64_t>(g_sim.jitter_ms));
        const int64_t j = jitter_dist(g_sim.rng);
        const int64_t result = static_cast<int64_t>(base_delay) + j;
        total_delay = (result > 0) ? static_cast<uint64_t>(result) : 0;
    }
    const uint64_t release_at = now_ms() + total_delay;

    // G4: Queue cap — evict oldest if at limit
    if (g_queue.size() >= 2048) {
        g_queue.pop_front();
    }

    // Enqueue
    QueuedPacket pkt;
    pkt.this_ptr      = self;
    pkt.socket_ptr    = socket;
    pkt.sys_addr      = std::move(sa_copy);
    pkt.bitstream_data = std::move(bs_copy);
    pkt.bits_used     = bits_used;
    pkt.rnr           = rnr;
    pkt.current_time  = current_time;
    pkt.release_at_ms = release_at;
    g_queue.push_back(std::move(pkt));

    ++g_sim.packets_delayed;
}

// ---------------------------------------------------------------------------
// Exported API
// ---------------------------------------------------------------------------

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_net_sim_enable(bool enable) {
    if (enable && !g_hooks_installed) {
        auto* ctx = InjectorCtx::instance();
        if (ctx == nullptr) {
            spdlog::warn("[NetSim] InjectorCtx unavailable — enable skipped");
            return;
        }

        auto* interceptor = ctx->GetGumInterceptor();
        if (interceptor == nullptr) {
            spdlog::warn("[NetSim] GumInterceptor unavailable — enable skipped");
            return;
        }

        GameNetworkSimInstallHook(interceptor);
        g_hooks_installed = true;
    }

    if (g_sim.enabled == enable) return;

    if (!enable && !g_queue.empty()) {
        // Flush all queued packets immediately on disable
        g_sim.is_releasing = true;
        for (const auto& pkt : g_queue) {
            flush_packet(pkt);
        }
        g_queue.clear();
        g_sim.is_releasing = false;
    }

    g_sim.enabled = enable;

    // Reset counters when toggling
    g_sim.packets_total    = 0;
    g_sim.packets_delayed  = 0;
    g_sim.packets_dropped  = 0;
    g_sim.packets_released = 0;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_net_sim_set(
    uint32_t delay_ms,
    uint32_t jitter_ms,
    uint32_t loss_pct)
{
    g_sim.delay_ms  = delay_ms;
    g_sim.jitter_ms = jitter_ms;
    g_sim.loss_pct  = (loss_pct > 100u) ? 100u : loss_pct;
}

DONTSTARVEINJECTOR_GAME_API void DS_LUAJIT_net_sim_update() {
    if (!g_sim.enabled || g_queue.empty()) return;

    const uint64_t now = now_ms();

    g_sim.is_releasing = true;

    auto it = g_queue.begin();
    while (it != g_queue.end()) {
        if (it->release_at_ms <= now) {
            flush_packet(*it);
            it = g_queue.erase(it);
        } else {
            ++it;
        }
    }

    g_sim.is_releasing = false;
}

DONTSTARVEINJECTOR_GAME_API const NetSimStats* DS_LUAJIT_net_sim_get_stats() {
    g_stats_cache.enabled          = g_sim.enabled;
    g_stats_cache.delay_ms         = g_sim.delay_ms;
    g_stats_cache.jitter_ms        = g_sim.jitter_ms;
    g_stats_cache.loss_pct         = g_sim.loss_pct;
    g_stats_cache.packets_total    = g_sim.packets_total;
    g_stats_cache.packets_delayed  = g_sim.packets_delayed;
    g_stats_cache.packets_dropped  = g_sim.packets_dropped;
    g_stats_cache.packets_released = g_sim.packets_released;
    g_stats_cache.queue_depth      = static_cast<uint32_t>(g_queue.size());
    return &g_stats_cache;
}

// ---------------------------------------------------------------------------
// Hook installation
// ---------------------------------------------------------------------------

void GameNetworkSimInstallHook(GumInterceptor* interceptor) {
    // ------------------------------------------------------------------
    // SendBitStream hook
    // Win x64 address: 0x14040a820 (confirmed via Ghidra)
    // Prologue bytes (address-independent):
    //   40 53 55 56 57 41 54 41 55 48 83 EC 68
    //   48 8B 05 ?? ?? ?? ??   (MOV RAX, [rip+...])
    //   48 33 C4               (XOR RAX, RSP — stack cookie)
    //   48 89 44 24 58         (MOV [RSP+58], RAX)
    //   41 8B 39               (MOV EDI, [R9] = numberOfBitsUsed)
    // ------------------------------------------------------------------
    static function_relocation::MemorySignature send_sig{
        "40 53 55 56 57 41 54 41 55 48 83 EC 68 "
        "48 8B 05 ?? ?? ?? ?? "
        "48 33 C4 "
        "48 89 44 24 58 "
        "41 8B 39 48",
        0
    };
    send_sig.only_one = true;
    send_sig.log      = true;

    if (send_sig.scan(nullptr)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(send_sig.target_address),
            reinterpret_cast<void*>(&hooked_SendBitStream),
            nullptr,
            reinterpret_cast<void**>(&original_SendBitStream));
        if (r == GUM_REPLACE_OK) {
            spdlog::info("[NetSim] hooked SendBitStream at {:x}",
                         send_sig.target_address);
        } else {
            spdlog::error("[NetSim] failed to hook SendBitStream: {}",
                          static_cast<int>(r));
        }
    } else {
        spdlog::warn("[NetSim] SendBitStream signature not found — net-sim disabled");
    }

    // ------------------------------------------------------------------
    // ~ReliabilityLayer destructor hook (MH7)
    // Win x64 address: 0x1404079f0 (FUN_1404079f0, confirmed via Ghidra)
    // Identified via:
    //   1. DS_MemoryPool.h string xrefs -> FUN_1404079f0
    //   2. Sets vtable ptr at start AND end (characteristic of destructor)
    //   3. Calls MemoryPool::Clear (FUN_140408520) 4 times
    //   4. Multiple DeleteCriticalSection calls matching macOS dtor pattern
    //   5. Calls FreeThreadSafeMemory equivalent (FUN_1403fb3a0)
    //
    // Bytes (offset 0..14 are stable prologue):
    //   48 89 5C 24 10   MOV [RSP+10h], RBX
    //   48 89 74 24 18   MOV [RSP+18h], RSI
    //   57               PUSH RDI
    //   48 83 EC 20      SUB RSP, 20h
    //   48 8D 05 ?? ?? ?? ??   LEA RAX, [vtable1]  <- RIP-relative, wildcard
    //   41 B9 03 00 00 00      MOV R9D, 3
    //   45 33 C0               XOR R8D, R8D
    //   48 89 01               MOV [RCX], RAX
    //   48 8D 05 ?? ?? ?? ??   LEA RAX, [vtable2]  <- RIP-relative, wildcard
    //   33 D2                  XOR EDX, EDX
    //   48 89 41 08            MOV [RCX+8], RAX
    // ------------------------------------------------------------------
    static function_relocation::MemorySignature dtor_sig{
        "48 89 5C 24 10 "
        "48 89 74 24 18 "
        "57 "
        "48 83 EC 20 "
        "48 8D 05 ?? ?? ?? ?? "
        "41 B9 03 00 00 00 "
        "45 33 C0 "
        "48 89 01 "
        "48 8D 05 ?? ?? ?? ?? "
        "33 D2 "
        "48 89 41 08 "
        "48",
        0
    };
    dtor_sig.only_one = true;
    dtor_sig.log      = true;

    if (dtor_sig.scan(nullptr)) {
        auto r = gum_interceptor_replace(
            interceptor,
            reinterpret_cast<void*>(dtor_sig.target_address),
            reinterpret_cast<void*>(&hooked_ReliabilityLayerDtor),
            nullptr,
            reinterpret_cast<void**>(&original_ReliabilityLayerDtor));
        if (r == GUM_REPLACE_OK) {
            spdlog::info("[NetSim] hooked ~ReliabilityLayer at {:x}",
                         dtor_sig.target_address);
        } else {
            spdlog::error("[NetSim] failed to hook ~ReliabilityLayer: {}",
                          static_cast<int>(r));
        }
    } else {
        // Non-fatal: without dtor hook, destroyed connections may briefly
        // appear alive in g_alive_instances. The flush_packet null-dereference
        // risk is low because packets are short-lived, but we warn.
        spdlog::warn("[NetSim] ~ReliabilityLayer signature not found — "
                     "connection lifecycle tracking disabled (packets may be "
                     "sent to stale connections after disconnect)");
    }
}

#endif // _WIN32
