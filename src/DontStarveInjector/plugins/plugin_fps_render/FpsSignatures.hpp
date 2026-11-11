#pragma once

// fps.render fixed signatures: the notebook-mode frame-time setter and (server
// only) its config gate.
//
// The consumer patches the four MOVSS immediates inside the setter, so the
// definition carries a read-only verifier that decodes exactly those constants
// from the matched window: a body that no longer holds 1/30, 1/60, 30 and 60 is
// a different function and must not be patched.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32)
#  define DS_SIG_HAVE_FPS_RENDER 1
#endif

#include "ProviderDesc.hpp"

namespace ds::fps_render {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::fps_render
