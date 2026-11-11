#pragma once
// Implementation-side descriptor for a plugin signature provider.
//
// A plugin (and the offline tool that links the same TU) declares one
// ProviderDesc: its owner, the static EntryDef table and an optional repair
// algorithm. `make_provider()` turns it into the POD ProviderV1 table that the
// SignatureManager (runtime) and the stateless runner (tools) call.
//
// This header is C++ only on purpose: it never crosses a module boundary. The
// boundary object is ds::sig::ProviderV1 from core/SignatureProvider.hpp, whose
// members are all POD.

#include "core/SignatureProvider.hpp"

#include "ModuleSections.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace ds::sig {

struct EntryDef;

// Read-only verifier for one entry.
//   target   resolved address the consumer would use
//   raw_hit  the raw pattern hit the address was derived from
// Returns false and fills `detail` when the decode contract does not hold. A
// verifier must not hook, write memory or touch the VM: it decodes/validates.
using VerifyFn = bool (*)(const EntryDef &def, const ContextView &ctx, uintptr_t target, uintptr_t raw_hit,
                          char *detail, size_t detail_cap);

// One stable signature. Everything here is static storage in the provider
// module; `patterns` is a candidate list (null-terminated) so a platform may
// keep more than one literal while still requiring a single total hit.
struct EntryDef {
    const char *owner = nullptr;
    const char *name = nullptr; // stable "<owner>.<symbol>"; never derived from the pattern
    const char *description = nullptr;
    const char *patterns[kMaxCandidates] = {};
    int32_t pattern_offset = 0;
    uint32_t platform_mask = kPlatformNone;
    uint32_t prot_flag = 0; // GUM page protection; 0 → execute|read
    int32_t hits_policy = static_cast<int32_t>(HitsPolicy::Unique);
    int32_t resolve_kind = static_cast<int32_t>(ResolveKind::RawOffset);
    int32_t definition_revision = 1; // bump when the scan/decode contract changes
    uint8_t client_only = 0;
    uint8_t server_only = 0;
    uint8_t audit_log = 1; // emit the shared "[signature] MISS" style line on failure
    uint8_t reserved = 0;
    VerifyFn verify = nullptr; // optional
};

// Optional repair hook. Only create/update call it; `failure` is the detail of
// the failed resolve. A repair result is accepted only after a full re-scan and
// verifier pass, so returning an unvalidated address is pointless.
using RepairFn = bool (*)(const EntryDef &def, const ContextView &ctx, const char *failure, ResolveReport &out);

struct ProviderDesc {
    const char *owner = nullptr;
    const char *provider_version = nullptr;
    const EntryDef *entries = nullptr;
    size_t entry_count = 0;
    RepairFn repair = nullptr;
    // Optional one-time initializer for entries whose pattern is generated at
    // runtime (e.g. a search string turned into hex). Called once, under a lock.
    void (*prepare)() = nullptr;
};

// Fills `out` with the POD table for `desc`. Returns false (and leaves `out`
// zeroed) when the descriptor is malformed.
bool make_provider(const ProviderDesc *desc, ProviderV1 *out);

// Section table of ctx.module_path (or the main module). Verifiers that need
// rodata or exact FDE ranges use this; failure means "fail closed".
bool module_sections_for(const ContextView &ctx, function_relocation::ModuleSections &out);

// Cache identity rules shared by the runtime path, the runner and the tools:
// module content digest, game version and the definition's rule set.
bool cache_identity_matches(const ContextView &ctx, const CacheRecord &rec, std::string &why);

// Runs the descriptor's optional repair algorithm and re-verifies its product
// through the normal scan/verify path. Only create/update call this.
bool repair_entry(const ProviderDesc &desc, const EntryDef &def, const ContextView &ctx, const char *failure,
                  ResolveReport &out);

// Platform / client-server applicability, shared by the runtime and the tools so
// one rule decides both.
inline bool entry_applicable(const EntryDef &def, const ContextView &ctx) {
    if ((def.platform_mask & ctx.platform) == 0) {
        return false;
    }
    if (def.client_only && !ctx.is_client) {
        return false;
    }
    if (def.server_only && ctx.is_client) {
        return false;
    }
    return def.patterns[0] != nullptr;
}

} // namespace ds::sig
