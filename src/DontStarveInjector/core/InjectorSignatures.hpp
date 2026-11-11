#pragma once

// Injector-owned (L0) signature entries.
//
// These run before any plugin is loaded: LoadGameModConfig() installs the
// SetThreadName replacement and DisableGameScriptsZip patches the script-bundle
// marker. Both therefore have to be registered with the SignatureManager before
// that call, and neither may depend on a plugin being present.

// This provider only exists for the targets that ship patterns for it: the
// switch below is the single place the condition is written, and the provider
// TU, the owning module_init and the offline tool all use it. It tests the
// compiler's platform macros so it never depends on include order.
#if defined(_WIN32) || defined(__linux__)
#  define DS_SIG_HAVE_INJECTOR 1
#endif

#include <string>

namespace ds::sig {

struct ProviderDesc;

// Definitions (the offline tool links this TU instead of the Injector).
const ProviderDesc &injector_provider_desc();

// Builds the provider and publishes it to the process-wide manager. Returns
// false (with a reason) when the descriptor or the registration is rejected.
bool register_injector_provider(std::string *detail);

} // namespace ds::sig
