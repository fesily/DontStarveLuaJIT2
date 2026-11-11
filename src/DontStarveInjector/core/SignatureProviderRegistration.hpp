#pragma once
// Shared module_init boilerplate: build the POD provider table from a plugin's
// ProviderDesc and stage it on the host (published only if init succeeds).
//
// Plugins only; the offline tools drive the same ProviderDesc through the
// stateless runner instead of the host.

#include "core/PluginHost.hpp"

#include "ProviderDesc.hpp"

#include <cstdio>

namespace ds::sig {

inline bool register_provider_with_host(ds::plugin::PluginHost *host, const ProviderDesc &desc, const char *tag) {
    if (!host) {
        return false;
    }
    ProviderV1 table{};
    if (!make_provider(&desc, &table) || !host->register_signature_provider(&table)) {
        // A rejected provider must be loud: the features that depend on it will
        // report "not resolved" at install time, and this line names the cause.
        std::fprintf(stderr, "[%s] signature provider registration rejected (owner=%s)\n", tag,
                     desc.owner ? desc.owner : "?");
        return false;
    }
    return true;
}

} // namespace ds::sig
