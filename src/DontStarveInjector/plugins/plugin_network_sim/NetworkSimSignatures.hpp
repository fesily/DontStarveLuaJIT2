#pragma once

// network.sim fixed signatures: BitStream::SendBitStream and
// ReliabilityLayer::~ReliabilityLayer.
//
// Both entries keep their "lazy install" contract: nothing here scans or hooks,
// the consumer resolves them when the feature is first enabled and degrades to a
// warning (not a failure) when one is missing.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32)
#  define DS_SIG_HAVE_NETWORK_SIM 1
#endif

#include "ProviderDesc.hpp"

namespace ds::network_sim {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::network_sim
