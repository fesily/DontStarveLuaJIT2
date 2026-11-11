#pragma once

// render.shadow fixed signatures.
//
// Every entry here is deliberately tolerant of multiple hits and selects the
// LOWEST address: several of these bodies exist more than once per build (inline
// clones), and the renderer always calls the first copy — a uniqueness rule would
// disable shading on a build where the previous code worked. The address is used
// as an identity value (vtable slots / rel32 targets), so the entries carry the
// rel32 windows as decode verifiers where the consumer depends on them.
//
// GenerateVB additionally hosts the helper call sites the consumer walks from its
// base: the verifier checks that each of those sites is still a rel32 call.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32)
#  define DS_SIG_HAVE_RENDER_SHADOW 1
#endif

#include "ProviderDesc.hpp"

namespace ds::shadow {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::shadow
