#pragma once
// Injector-side signature resolution entry point for plugins.
//
// A plugin never scans for itself any more: it asks the Injector's
// SignatureManager for the entry it declared (<owner>.<symbol>), and the Manager
// picks the registered provider, applies the definition's rules and memoizes the
// verified address for the process lifetime. Names are stable across game
// updates, so a plugin never learns a pattern.
//
// Call at hook-install time only (never from a frame callback): the first query
// may scan the target module once.

#include "core/SignatureProvider.hpp"

#include "config/InjectorHostConfig.hpp"

#include <cstdint>

// POD results only: the report is filled by the caller's provider run inside the
// Injector, so no STL type and no ownership crosses the module boundary.
//   *target_address is set only when the result is Resolved (0).
// NotApplicable (1) means the entry does not exist for this client/server or
// platform, which a caller treats like a missing feature, not like a crash.
DONTSTARVEINJECTOR_API int32_t ds_signature_resolve_ex(const char *name, uint64_t *target_address, char *detail,
                                                       uint32_t detail_cap);

namespace ds::sig {

// Plugin-side helper over the exported entry point: fills `out` (status,
// address, detail) and answers whether the entry resolved.
inline bool host_resolve(const char *name, ResolveReport *out) {
    if (!out) {
        return false;
    }
    *out = ResolveReport{};
    uint64_t address = 0;
    const int32_t status = ds_signature_resolve_ex(name, &address, out->detail, sizeof(out->detail));
    out->status = static_cast<ResolveStatus>(status);
    out->target_va = address;
    return out->status == ResolveStatus::Resolved;
}

} // namespace ds::sig
