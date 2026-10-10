#pragma once
#include <cstdint>
#include <expected>
#include <string>

namespace ds::net_stats {

// Structure offsets re-derived from the decoded cNetworkClientObject2::UpdateNetStats
// code window (never hardcoded). The anchor itself comes from a byte signature.
//
//   listingOff            : this + off = cPlayerListingData (std::string userid @ +0)
//                           — the userid is the key the RTT is published under
//   ringPtrOff            : this + off = pointer to the N-slot stats ring; its
//                           newest slot holds the RTT the engine measured for
//                           this tick (clamped to 99999 when invalid)
//   indexOff              : this + off = int8 index of the newest ring slot
//   ringWindow/ringStride : slot count and bytes per slot
//
// Every rule is hard: any failure disables the feature (fail closed) so the engine
// behaviour is left untouched.
struct NetStatsLayout {
    uint32_t listingOff = 0;
    uint32_t ringPtrOff = 0;
    uint32_t indexOff = 0;
    uint32_t ringWindow = 0;
    uint32_t ringStride = 0;
};

// Decodes the layout from the code window starting at `entry` (the signature hit).
// Returns the layout, or the failure reason when a rule breaks.
//
// The calling convention selects the argument register of the decoded function
// (Host = the running platform; MsX64/SysV exist so both measured shapes stay
// testable from either host).
enum class PingCallConv : uint8_t {
    Host,   // MS-x64 on Windows, SysV elsewhere
    MsX64,  // this=RCX
    SysV,   // this=RDI
};

std::expected<NetStatsLayout, std::string> decode_net_stats(uintptr_t entry,
                                                            PingCallConv conv = PingCallConv::Host);

} // namespace ds::net_stats
