#pragma once

// debug.profiler fixed signatures: FrameProfiler::Push / Pop (and the Linux
// singleton wrapper of Push).
//
// macOS has no shape for these yet — the previous implementation returned 0
// before scanning — so no macOS definition is registered and the entries simply
// report NotApplicable there. Registering a dead pattern as "supported" is the
// failure mode this file must not repeat.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32) || defined(__linux__)
#  define DS_SIG_HAVE_DEBUG_PROFILER 1
#endif

#include "ProviderDesc.hpp"

namespace ds::debug_profiler {

const ds::sig::ProviderDesc &signature_provider();

} // namespace ds::debug_profiler
