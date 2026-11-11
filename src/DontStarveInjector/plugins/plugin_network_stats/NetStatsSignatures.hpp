#pragma once

// network.stats fixed signatures: the cNetworkClientObject2::UpdateNetStats anchor.
//
// One stable name, one or more candidate literals per platform, and the rule the
// previous inline loop implemented: the *combined* hit count across all candidates
// must be exactly one. That total-hit semantics is what the entry carries, so a
// second literal can never quietly turn "the anchor" into "one of two" — and the
// candidate list is not deduplicated, so a literal present twice still fails.
//
// The definition's verifier runs decode_net_stats() on the anchor and fails the
// entry when the layout rules break: a matched window that is not the stats
// updater must never be handed to the hook.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32) || defined(__linux__)
#  define DS_SIG_HAVE_NETWORK_STATS 1
#endif

#include "ProviderDesc.hpp"

namespace ds::net_stats {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::net_stats
