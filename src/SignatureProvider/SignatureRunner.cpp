#include "SignatureRunner.hpp"

#include "SignatureCache.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace ds::sig {
namespace {

// Applicability, with the Unsupported case kept separate from NotApplicable: an
// entry that exists for this platform but has no pattern yet is a provider gap,
// not a target that legitimately has no such symbol.
bool classify_applicable(const EntryDef &def, const ContextView &ctx, ResolveStatus &status) {
    if ((def.platform_mask & ctx.platform) == 0) {
        status = ResolveStatus::NotApplicable;
        return false;
    }
    if (def.client_only && !ctx.is_client) {
        status = ResolveStatus::NotApplicable;
        return false;
    }
    if (def.server_only && ctx.is_client) {
        status = ResolveStatus::NotApplicable;
        return false;
    }
    if (def.patterns[0] == nullptr) {
        status = ResolveStatus::Unsupported;
        return false;
    }
    return true;
}

void to_record(const ResolveReport &report, CacheRecord &record) {
    record = CacheRecord{};
    record.status = CacheStatus::Ok;
    record.pattern_offset = report.pattern_offset;
    record.hits_policy = report.hits_policy;
    record.resolve_kind = report.resolve_kind;
    record.definition_revision = report.definition_revision;
    record.platform_mask = report.platform_mask;
    record.client_only = report.client_only;
    record.raw_hit_count = std::min<uint32_t>(report.raw_hit_count, kMaxHits);
    for (uint32_t i = 0; i < record.raw_hit_count; ++i) {
        record.raw_hit_rvas[i] = report.raw_hit_rvas[i];
    }
    record.target_rva = report.target_rva;
    std::copy(std::begin(report.pattern), std::end(report.pattern), std::begin(record.pattern));
}

// A check run must prove the stored record still describes this exact target and
// definition before its RVA is compared with the fresh scan.
bool check_cached_record(const EntryDef &def, const ContextView &ctx, const ResolveReport &scanned,
                         EntryOutcome &out) {
    CacheRecord record{};
    char detail[kMaxDetailLen] = {};
    const auto status =
            cache_read_entry(ctx.cache_path, ctx.platform, def.owner, def.name, &record, detail, sizeof(detail));
    out.cache = status;
    if (status != CacheStatus::Ok) {
        out.detail = detail[0] ? detail : "cache record unavailable";
        return false;
    }
    std::string why;
    if (!cache_identity_matches(ctx, record, why)) {
        out.cache = CacheStatus::Stale;
        out.detail = why;
        return false;
    }
    if (record.pattern_offset != def.pattern_offset || record.hits_policy != def.hits_policy ||
        record.resolve_kind != def.resolve_kind || record.definition_revision != def.definition_revision) {
        out.cache = CacheStatus::Stale;
        out.detail = "cached rule set differs from the current definition";
        return false;
    }
    if (record.target_rva != scanned.target_rva) {
        out.cache = CacheStatus::Ambiguous;
        out.detail = "cached target RVA differs from the verified one";
        return false;
    }
    // The stored raw hit must still be the hit the fresh scan selected: a new
    // lower-address candidate (lowest policy) or a second hit (unique policy)
    // invalidates the entry even when the old address still matches bytes.
    bool raw_seen = false;
    for (uint32_t i = 0; i < record.raw_hit_count; ++i) {
        raw_seen = raw_seen || record.raw_hit_rvas[i] == scanned.raw_hit_rvas[0];
    }
    if (!raw_seen) {
        out.cache = CacheStatus::Stale;
        out.detail = "cached raw hit is no longer the hit the scan selects";
        return false;
    }
    if (std::strcmp(record.pattern, scanned.pattern) != 0) {
        out.cache = CacheStatus::Stale;
        out.detail = "cached pattern differs from the one that now matches";
        return false;
    }
    out.cache = CacheStatus::Ok;
    return true;
}

} // namespace

const char *runner_mode_name(RunnerMode mode) {
    switch (mode) {
    case RunnerMode::Create:
        return "create";
    case RunnerMode::Update:
        return "update";
    default:
        return "check";
    }
}

const char *resolve_status_name(ResolveStatus status) {
    switch (status) {
    case ResolveStatus::Resolved:
        return "resolved";
    case ResolveStatus::NotApplicable:
        return "not-applicable";
    case ResolveStatus::Unsupported:
        return "unsupported";
    case ResolveStatus::ModuleUnavailable:
        return "module-unavailable";
    case ResolveStatus::PatternMissing:
        return "pattern-missing";
    case ResolveStatus::PatternAmbiguous:
        return "pattern-ambiguous";
    case ResolveStatus::OffsetOutOfRange:
        return "offset-out-of-range";
    case ResolveStatus::DecodeFailed:
        return "decode-failed";
    case ResolveStatus::CacheMissing:
        return "cache-missing";
    default:
        return "internal";
    }
}

const char *cache_status_name(CacheStatus status) {
    switch (status) {
    case CacheStatus::NotRequested:
        return "none";
    case CacheStatus::Ok:
        return "ok";
    case CacheStatus::MissingFile:
        return "missing-file";
    case CacheStatus::MissingEntry:
        return "missing-entry";
    case CacheStatus::InvalidFile:
        return "invalid-file";
    case CacheStatus::Stale:
        return "stale";
    case CacheStatus::OutOfRange:
        return "out-of-range";
    case CacheStatus::Ambiguous:
        return "ambiguous";
    default:
        return "unknown";
    }
}

RunnerReport run_provider(const ProviderDesc &desc, const ContextView &ctx, RunnerMode mode) {
    RunnerReport report;
    ProviderV1 table{};
    if (!make_provider(&desc, &table)) {
        EntryOutcome failure;
        failure.owner = desc.owner ? desc.owner : "";
        failure.detail = "provider descriptor is malformed";
        failure.status = ResolveStatus::Internal;
        report.entries.push_back(std::move(failure));
        report.ok = false;
        return report;
    }

    struct PendingWrite {
        std::string name;
        CacheRecord record;
    };
    std::vector<PendingWrite> pending;
    const char *writer_owner = desc.owner ? desc.owner : "";
    bool wrote = false;
    std::string write_detail;

    auto flush = [&]() {
        if (mode == RunnerMode::Check || pending.empty() || !ctx.cache_path || !*ctx.cache_path) {
            pending.clear();
            return;
        }
        std::vector<CacheWriteEntry> entries;
        entries.reserve(pending.size());
        for (const auto &item : pending) {
            entries.push_back(CacheWriteEntry{item.name.c_str(), &item.record});
        }
        CacheFileIdentity identity{};
        if (ctx.game_version) {
            std::snprintf(identity.game_version, sizeof(identity.game_version), "%s", ctx.game_version);
        }
        if (ctx.module_digest) {
            std::snprintf(identity.module_digest, sizeof(identity.module_digest), "%s", ctx.module_digest);
        }
        identity.module_size = ctx.module_size;
        char detail[kMaxDetailLen] = {};
        if (!cache_write_owner(ctx.cache_path, ctx.platform, writer_owner, identity, entries.data(),
                               entries.size(), detail, sizeof(detail))) {
            write_detail = detail[0] ? detail : "cache write failed";
            wrote = false;
        } else {
            wrote = true;
        }
        pending.clear();
    };

    // One run per stable name. A name may carry several platform variants; the
    // variant that applies to this target is the one reported (and, when none
    // applies, a single NotApplicable line stands in for all of them).
    auto report_defs = [&]() {
        std::vector<const EntryDef *> defs;
        for (size_t i = 0; i < desc.entry_count; ++i) {
            const EntryDef *def = &desc.entries[i];
            if (!def->name) {
                continue;
            }
            bool seen = false;
            for (const auto *existing : defs) {
                seen = seen || std::strcmp(existing->name, def->name) == 0;
            }
            if (seen) {
                continue;
            }
            for (size_t j = i + 1; j < desc.entry_count; ++j) {
                const auto &other = desc.entries[j];
                if (other.name && std::strcmp(other.name, def->name) == 0 &&
                    (other.platform_mask & ctx.platform) != 0) {
                    def = &other;
                    break;
                }
            }
            defs.push_back(def);
        }
        return defs;
    };

    auto run_def = [&](const EntryDef &def) {
        EntryOutcome outcome;
        outcome.owner = def.owner ? def.owner : "";
        outcome.name = def.name ? def.name : "";
        ResolveStatus applicability = ResolveStatus::Resolved;
        if (!classify_applicable(def, ctx, applicability)) {
            outcome.status = applicability;
            report.entries.push_back(std::move(outcome));
            return;
        }
        outcome.applicable = true;
        report.applicable_seen = true;

        // Every mode scans from the definition. create/update need a freshly
        // verified address, and check must prove the *whole* range rule (unique /
        // lowest / combined hit) instead of re-validating the bytes at the stored
        // address — otherwise a record that is locally correct but ambiguous
        // elsewhere would pass. The stored record is compared afterwards.
        ContextView scan_ctx = ctx;
        scan_ctx.cache_path = nullptr;
        ResolveReport resolved{};
        bool ok = table.resolve(table.self, def.name, &scan_ctx, &resolved);
        outcome.cache = resolved.cache_status;
        if (!ok && mode != RunnerMode::Check && table.repair) {
            ResolveReport repaired{};
            if (table.repair(table.self, def.name, &scan_ctx,
                             resolved.detail[0] ? resolved.detail : "resolve failed", &repaired)) {
                resolved = repaired;
                ok = true;
            } else {
                outcome.detail = repaired.detail[0] ? repaired.detail : resolved.detail;
            }
        }

        if (!ok) {
            outcome.status = resolved.status;
            if (outcome.detail.empty()) {
                outcome.detail = resolved.detail;
            }
            if (mode == RunnerMode::Check) {
                // Report the cache state so a missing record is distinguishable
                // from a record that no longer verifies.
                CacheRecord record{};
                char detail[kMaxDetailLen] = {};
                outcome.cache = cache_read_entry(ctx.cache_path, ctx.platform, def.owner, def.name, &record, detail,
                                                 sizeof(detail));
                if (outcome.detail.empty() && detail[0]) {
                    outcome.detail = detail;
                }
            }
            report.ok = false;
            report.entries.push_back(std::move(outcome));
            return;
        }

        outcome.status = ResolveStatus::Resolved;
        outcome.repaired = resolved.repaired != 0;
        outcome.rva = resolved.target_rva;
        outcome.raw_hits = resolved.raw_hit_count;
        if (mode == RunnerMode::Check) {
            if (!check_cached_record(def, ctx, resolved, outcome)) {
                if (outcome.detail.empty()) {
                    outcome.detail = "stored record does not match the verified entry";
                }
                // "No usable stored record" and "stored record no longer verifies"
                // are different failures for the caller.
                outcome.status = outcome.cache == CacheStatus::Ok ? ResolveStatus::DecodeFailed
                                                                 : ResolveStatus::CacheMissing;
                report.ok = false;
            }
        } else {
            PendingWrite item;
            item.name = outcome.name;
            to_record(resolved, item.record);
            pending.push_back(std::move(item));
        }
        report.entries.push_back(std::move(outcome));
    };

    for (const auto *def : report_defs()) {
        run_def(*def);
    }

    flush();
    if (mode != RunnerMode::Check && report.applicable_seen) {
        OwnerOutcome owner;
        owner.owner = writer_owner;
        owner.wrote_cache = wrote;
        owner.write_detail = write_detail;
        if (!wrote && !write_detail.empty()) {
            // A run that verified entries but could not persist them is a
            // failure: the next launch would regenerate from scratch.
            report.ok = false;
        }
        report.owners.push_back(std::move(owner));
    }
    return report;
}

} // namespace ds::sig
