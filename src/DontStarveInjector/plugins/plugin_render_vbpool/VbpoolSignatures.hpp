#pragma once

// render.vbpool fixed signatures: HWBuffer::Init, HWBuffer::~HWBuffer and
// Batcher::Flush.
//
// The consumer's install order is a dependency (dtor hook needs the pool, Flush
// needs both), so it keeps installing them in that order; this file only owns the
// definitions.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32)
#  define DS_SIG_HAVE_RENDER_VBPOOL 1
#endif

#include "ProviderDesc.hpp"

namespace ds::render_vbpool {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::render_vbpool
