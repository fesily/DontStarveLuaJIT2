#pragma once
// Process-wide fixed-signature manager (Injector only).
//
// One instance holds: the target context every provider needs (platform, main
// module, client/server, game version, content digest, cache path), the registry
// of providers published during the plugins' module_init window, and the memo of
// verified addresses. It never rewrites the cache and never repairs an entry:
// that is what the offline tool's create/update modes are for.

#include "core/SignatureProvider.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ds::sig {

struct RuntimeTarget {
    uint32_t platform = kPlatformNone;
    bool is_client = true;
    std::string module_path;
    uint64_t module_base = 0;
    uint64_t module_size = 0;
    std::string game_version;
};

// Called once, early in Inject(): after the client/server role is known and
// before the first consumer (L0 SetThreadName) installs a hook.
void configure_runtime(const RuntimeTarget &target);
RuntimeTarget runtime_target();

// Structure/duplicate validation, callable before the provider is published so a
// module_init can fail on a bad descriptor instead of silently publishing half a
// provider.
bool validate_provider(const ProviderV1 *provider, std::string *detail);

// Publishes a provider (its POD table is copied). Returns false on an invalid
// descriptor or a duplicate owner/entry name; nothing is published in that case.
bool add_provider(const ProviderV1 *provider, std::string *detail);

// Resolve one entry by "<owner>.<symbol>". Memoized for the process lifetime, so
// a second query after the caller's own hook is installed never re-scans bytes
// the hook may have patched.
bool resolve_entry(const char *name, ResolveReport *out);

// Diagnostics: registered providers and their entry counts.
std::vector<std::string> provider_owners();

} // namespace ds::sig
