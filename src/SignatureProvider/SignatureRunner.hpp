#pragma once
// Stateless create/update/check runner for fixed signature providers.
//
// The offline tools use this over an explicit provider table (they never load
// the plugin DLLs). The Injector's SignatureManager does not: at runtime a
// provider is only ever asked to resolve, never to create, repair or write.

#include "ProviderDesc.hpp"

#include <string>
#include <vector>

namespace ds::sig {

enum class RunnerMode {
    Create, // full scan, ignore the stored DB, write every verified record
    Update, // read+validate the DB, full scan, repair only when a re-scan still fails
    Check,  // read-only: parse the DB, full scan, compare; never writes or repairs
};

struct EntryOutcome {
    std::string owner;
    std::string name;
    ResolveStatus status = ResolveStatus::Internal;
    CacheStatus cache = CacheStatus::NotRequested;
    bool applicable = false;
    bool repaired = false;
    uint64_t rva = 0;
    uint32_t raw_hits = 0;
    std::string detail;
};

struct OwnerOutcome {
    std::string owner;
    bool wrote_cache = false;
    std::string write_detail;
};

struct RunnerReport {
    std::vector<EntryOutcome> entries;
    std::vector<OwnerOutcome> owners;
    bool ok = true;
    bool applicable_seen = false;
};

// Runs every entry of one provider for one target. Failures of one entry never
// stop the others; `report.ok` is false when any applicable entry failed.
RunnerReport run_provider(const ProviderDesc &desc, const ContextView &ctx, RunnerMode mode);

const char *runner_mode_name(RunnerMode mode);
const char *resolve_status_name(ResolveStatus status);
const char *cache_status_name(CacheStatus status);

} // namespace ds::sig
