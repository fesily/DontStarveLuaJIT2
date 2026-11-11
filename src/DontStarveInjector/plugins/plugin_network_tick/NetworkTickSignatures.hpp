#pragma once

// network.tick fixed signatures: the three literals DS_LUAJIT_replace_network_tick
// rewrites.
//
// All three resolve to an *internal* byte of their function (a `mov imm8` operand,
// a `lea` displacement), not to a function entry: the consumer writes a single
// byte at that address, so the offset is part of the contract and each entry is a
// plain RawOffset definition.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32)
#  define DS_SIG_HAVE_NETWORK_TICK 1
#endif

#include "ProviderDesc.hpp"

namespace ds::network_tick {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::network_tick
