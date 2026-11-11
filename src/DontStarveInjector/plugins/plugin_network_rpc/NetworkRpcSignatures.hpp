#pragma once

// network.rpc fixed signatures: RakNet RPC4::Signal, the entity channel/ordering
// hooks (NetworkComponent serialize + ReliabilityLayer ordered-stream arrays +
// the NetworkComponentReplica3 constructor that identifies the vtable).
//
// These are the definitions the plugin's GameNetWorkHookRpc4 installs its probes
// from. There is no repair path: each literal is a full prologue, so a miss means
// the engine changed shape and the feature has to be re-derived by hand.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32)
#  define DS_SIG_HAVE_NETWORK_RPC 1
#endif

#include "ProviderDesc.hpp"

namespace ds::network_rpc {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::network_rpc
