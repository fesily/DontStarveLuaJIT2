#pragma once
// Explicit provider table for the offline tools.
//
// The tools must be able to check every repository provider WITHOUT loading the
// Injector or a single plugin DLL, so each provider TU is linked in directly and
// listed here once. This is the only place a new provider has to be added for the
// tools to see it — there is no second hand-written pattern list and no text
// scraping of .cpp files.

#include "ProviderDesc.hpp"

#include <vector>

namespace ds::sig {

struct ProviderBinding {
    const char *owner;
    const ProviderDesc &(*desc)();
};

// Every provider shipped with the repository, in a stable order.
const std::vector<ProviderBinding> &repository_providers();

} // namespace ds::sig
