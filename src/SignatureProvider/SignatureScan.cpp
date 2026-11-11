#include "ProviderDesc.hpp"
#include "SignatureCache.hpp"

#include "FunctionRanges.hpp"
#include "MemorySignature.hpp"
#include "ModuleSections.hpp"

#include <frida-gum.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace ds::sig {

uint32_t host_platform() {
#if defined(DS_SIG_TARGET_WINDOWS_X64)
    return kPlatformWindowsX64;
#elif defined(DS_SIG_TARGET_LINUX_X64)
    return kPlatformLinuxX64;
#elif defined(DS_SIG_TARGET_MACOS_ARM64)
    return kPlatformMacosArm64;
#elif defined(DS_SIG_TARGET_MACOS_X64)
    return kPlatformMacosX64;
#else
    return kPlatformNone; // not a target this project builds
#endif
}

const char *platform_name(uint32_t platform) {
    switch (platform) {
    case kPlatformWindowsX64:
        return "windows-x64";
    case kPlatformLinuxX64:
        return "linux-x64";
    case kPlatformMacosX64:
        return "macos-x64";
    case kPlatformMacosArm64:
        return "macos-arm64";
    default:
        return "unknown";
    }
}

namespace {

void copy_text(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) {
        return;
    }
    const size_t n = src ? std::strlen(src) : 0;
    const size_t write = n < cap - 1 ? n : cap - 1;
    if (write) {
        std::memcpy(dst, src, write);
    }
    dst[write] = '\0';
}

void set_detail(char *dst, size_t cap, const std::string &text) {
    copy_text(dst, cap, text.c_str());
}

// A stable name may be defined more than once as long as the definitions cover
// disjoint platforms (the same symbol has different patterns *and* different
// address rules per platform). The first definition whose mask covers the
// target platform wins; a name with no matching definition is NotApplicable.
const EntryDef *find_entry(const ProviderDesc *desc, const char *name, uint32_t platform) {
    if (!desc || !name) {
        return nullptr;
    }
    const EntryDef *fallback = nullptr;
    for (size_t i = 0; i < desc->entry_count; ++i) {
        const auto &def = desc->entries[i];
        if (!def.name || std::strcmp(def.name, name) != 0) {
            continue;
        }
        if ((def.platform_mask & platform) != 0) {
            return &def;
        }
        if (!fallback) {
            fallback = &def;
        }
    }
    return fallback;
}

void fill_meta_impl(const EntryDef &def, ResolveReport &out) {
    out.pattern_offset = def.pattern_offset;
    out.hits_policy = def.hits_policy;
    out.resolve_kind = def.resolve_kind;
    out.definition_revision = def.definition_revision;
    out.platform_mask = def.platform_mask;
    out.client_only = def.client_only;
}

uint32_t scan_prot_flag(const EntryDef &def) {
    return def.prot_flag ? def.prot_flag : static_cast<uint32_t>(GUM_PAGE_EXECUTE | GUM_PAGE_READ);
}

// Byte length of a wildcard pattern: one byte per space-separated token.
size_t pattern_window_bytes(const char *pattern) {
    if (!pattern || !*pattern) {
        return 0;
    }
    size_t tokens = 0;
    bool in_token = false;
    for (const char *p = pattern; *p; ++p) {
        if (*p == ' ') {
            in_token = false;
        } else if (!in_token) {
            in_token = true;
            ++tokens;
        }
    }
    return tokens;
}

bool in_module(const ContextView &ctx, uintptr_t address) {
    if (ctx.module_size == 0) {
        // Range unknown (offline image without a size): the scan already bounded
        // the hits, so nothing more can be rejected here.
        return true;
    }
    return address >= ctx.module_base && address - ctx.module_base < ctx.module_size;
}

struct RawHit {
    uintptr_t address = 0;
    const char *pattern = nullptr;
};

void audit_miss(const EntryDef &def, const ContextView &ctx, const char *reason, size_t hits,
                const std::string &extra = {}) {
    if (!def.audit_log) {
        return;
    }
    auto log = spdlog::get("FunctionRelocation");
    if (!log) {
        log = spdlog::default_logger();
    }
    if (!log) {
        return;
    }
    log->warn("[signature] MISS owner={} name={} reason={} hits={} module=\"{}\" pattern=\"{}\"{}", def.owner,
              def.name, reason, hits, ctx.module_path ? ctx.module_path : "<main module>",
              def.patterns[0] ? def.patterns[0] : "<null>", extra.empty() ? "" : " " + extra);
}

// Resolves the consumer address of one raw hit and records the same mapping for
// every hit so the caller (and the cache) sees raw and resolved RVAs together.
bool resolve_hit(const EntryDef &def, const ContextView &ctx, uintptr_t raw, bool have_sections,
                 function_relocation::ModuleSections &sections, std::string &why) {
    uintptr_t target = 0;
    if (static_cast<ResolveKind>(def.resolve_kind) == ResolveKind::FdeEntry) {
        if (!have_sections) {
            why = "module sections unavailable for FDE entry resolution";
            return false;
        }
        const auto hit = raw - static_cast<intptr_t>(def.pattern_offset);
        target = function_relocation::resolve_function_entry(sections, hit);
        if (target == 0) {
            why = "raw hit does not map to an exact FDE function entry";
            return false;
        }
    } else {
        target = raw + def.pattern_offset;
    }
    if (!in_module(ctx, target)) {
        why = "resolved address is outside the module";
        return false;
    }
    return true;
}

uintptr_t resolved_va(const EntryDef &def, const ContextView &ctx, uintptr_t raw, bool have_sections,
                      function_relocation::ModuleSections &sections) {
    if (static_cast<ResolveKind>(def.resolve_kind) == ResolveKind::FdeEntry) {
        if (!have_sections) {
            return 0;
        }
        return function_relocation::resolve_function_entry(sections,
                                                           raw - static_cast<intptr_t>(def.pattern_offset));
    }
    return raw + def.pattern_offset;
}

// Does the cache record still describe this exact target and definition?
bool cache_rules_match(const EntryDef &def, const ContextView &ctx, const CacheRecord &rec,
                       std::string &why) {
    if (rec.pattern_offset != def.pattern_offset || rec.hits_policy != def.hits_policy ||
        rec.resolve_kind != def.resolve_kind) {
        why = "cached rule set differs from the current definition";
        return false;
    }
    if (rec.definition_revision != def.definition_revision) {
        why = "cached definition revision differs from the current one";
        return false;
    }
    if ((rec.platform_mask & ctx.platform) == 0) {
        why = "cached record does not cover this platform";
        return false;
    }
    if ((rec.client_only != 0) != (def.client_only != 0)) {
        why = "cached client/server applicability differs";
        return false;
    }
    const char *digest = ctx.module_digest ? ctx.module_digest : "";
    if (digest[0] != '\0' && std::strcmp(rec.module_digest, digest) != 0) {
        why = "cached module content digest differs from the target binary";
        return false;
    }
    const char *version = ctx.game_version ? ctx.game_version : "";
    if (version[0] != '\0' && rec.game_version[0] != '\0' && std::strcmp(rec.game_version, version) != 0) {
        why = "cached game version differs from the target";
        return false;
    }
    return true;
}

bool verify_target(const EntryDef &def, const ContextView &ctx, uintptr_t target, uintptr_t raw,
                   ResolveReport &out) {
    if (!def.verify) {
        return true;
    }
    char detail[kMaxDetailLen] = {};
    if (def.verify(def, ctx, target, raw, detail, sizeof(detail))) {
        return true;
    }
    set_detail(out.detail, sizeof(out.detail), detail[0] ? detail : "read-only verifier rejected the address");
    out.status = ResolveStatus::DecodeFailed;
    return false;
}

// Runtime cache reuse: the recorded raw hit must still carry the pattern bytes,
// the record must still derive the recorded target, and the decode contract must
// hold. A full uniqueness scan belongs to the offline check, not to a hook-time
// resolve.
bool validate_cached(const EntryDef &def, const ContextView &ctx, const CacheRecord &rec, ResolveReport &out,
                     std::string &why) {
    if (rec.raw_hit_count == 0) {
        why = "cached record has no raw hit RVA";
        return false;
    }
    const uintptr_t raw = ctx.module_base + static_cast<uintptr_t>(rec.raw_hit_rvas[0]);
    if (!in_module(ctx, raw) ||
        (ctx.module_size != 0 && static_cast<uintptr_t>(rec.target_rva) >= ctx.module_size)) {
        out.cache_status = CacheStatus::OutOfRange;
        why = "cached RVAs are outside the target module";
        return false;
    }
    // Re-match the recorded pattern inside a window of exactly its own length:
    // the bytes at the cached raw RVA must still be the ones that were verified.
    function_relocation::MemorySignature probe{rec.pattern, 0, false};
    probe.log = false;
    probe.prot_flag = scan_prot_flag(def);
    const size_t window = pattern_window_bytes(rec.pattern);
    if (window == 0) {
        out.cache_status = CacheStatus::InvalidFile;
        why = "cached pattern is unusable";
        return false;
    }
    probe.scan(raw, window);
    if (probe.targets.size() != 1 || probe.targets.front() != raw) {
        out.cache_status = CacheStatus::Ambiguous;
        why = "cached raw hit no longer matches its pattern bytes";
        return false;
    }
    function_relocation::ModuleSections sections{};
    const bool have_sections = static_cast<ResolveKind>(def.resolve_kind) == ResolveKind::FdeEntry &&
                               module_sections_for(ctx, sections);
    std::string resolve_why;
    if (!resolve_hit(def, ctx, raw, have_sections, sections, resolve_why)) {
        out.cache_status = CacheStatus::OutOfRange;
        why = resolve_why;
        return false;
    }
    const auto target = resolved_va(def, ctx, raw, have_sections, sections);
    if (target != ctx.module_base + static_cast<uintptr_t>(rec.target_rva)) {
        out.cache_status = CacheStatus::Stale;
        why = "cached target RVA no longer follows from its raw hit";
        return false;
    }
    if (!verify_target(def, ctx, target, raw, out)) {
        out.cache_status = CacheStatus::Stale;
        why = out.detail;
        return false;
    }
    out.status = ResolveStatus::Resolved;
    out.cache_status = CacheStatus::Ok;
    out.from_cache = 1;
    out.target_va = target;
    out.target_rva = target - ctx.module_base;
    out.raw_hit_count = rec.raw_hit_count;
    out.hit_count = rec.raw_hit_count < kMaxHits ? rec.raw_hit_count : kMaxHits;
    for (uint32_t i = 0; i < out.hit_count; ++i) {
        out.raw_hit_rvas[i] = rec.raw_hit_rvas[i];
        out.target_rvas[i] = rec.target_rva;
    }
    copy_text(out.pattern, sizeof(out.pattern), rec.pattern);
    return true;
}

bool scan_entry_impl(const EntryDef &def, const ContextView &ctx, ResolveReport &out) {
    std::vector<RawHit> hits;
    for (size_t i = 0; i < kMaxCandidates && def.patterns[i] != nullptr; ++i) {
        function_relocation::MemorySignature sig{def.patterns[i], 0, false};
        sig.log = false;
        sig.prot_flag = scan_prot_flag(def);
        sig.scan(ctx.module_path);
        for (const auto address : sig.targets) {
            hits.push_back(RawHit{address, def.patterns[i]});
        }
    }
    std::sort(hits.begin(), hits.end(), [](const RawHit &l, const RawHit &r) { return l.address < r.address; });
    out.raw_hit_count = static_cast<uint32_t>(hits.size());
    out.hit_count = static_cast<uint32_t>(std::min<size_t>(hits.size(), kMaxHits));
    out.target_va = 0;

    function_relocation::ModuleSections sections{};
    const bool need_sections = static_cast<ResolveKind>(def.resolve_kind) == ResolveKind::FdeEntry;
    const bool have_sections = need_sections && module_sections_for(ctx, sections);

    for (uint32_t i = 0; i < out.hit_count; ++i) {
        out.raw_hit_rvas[i] = hits[i].address - ctx.module_base;
        const auto va = resolved_va(def, ctx, hits[i].address, have_sections, sections);
        out.target_rvas[i] = va ? va - ctx.module_base : 0;
    }

    if (hits.empty()) {
        out.status = ResolveStatus::PatternMissing;
        set_detail(out.detail, sizeof(out.detail), "no raw pattern hit in the target module");
        audit_miss(def, ctx, "no_hit", 0);
        return false;
    }

    const auto policy = static_cast<HitsPolicy>(def.hits_policy);
    std::vector<const RawHit *> ordered;
    ordered.reserve(hits.size());
    for (const auto &hit : hits) {
        ordered.push_back(&hit);
    }
    if (policy == HitsPolicy::Unique && ordered.size() != 1) {
        out.status = ResolveStatus::PatternAmbiguous;
        set_detail(out.detail, sizeof(out.detail), "more than one raw pattern hit where exactly one is required");
        audit_miss(def, ctx, "ambiguous", ordered.size());
        return false;
    }
    if (policy == HitsPolicy::Unique) {
        ordered.resize(1);
    }

    std::string why;
    for (const auto *hit : ordered) {
        if (!resolve_hit(def, ctx, hit->address, have_sections, sections, why)) {
            out.status = ResolveStatus::OffsetOutOfRange;
            set_detail(out.detail, sizeof(out.detail), why);
            audit_miss(def, ctx, "bad_address", ordered.size(), why);
            return false;
        }
        const auto target = resolved_va(def, ctx, hit->address, have_sections, sections);
        if (policy == HitsPolicy::FilteredLowest) {
            if (!verify_target(def, ctx, target, hit->address, out)) {
                continue; // try the next (higher) candidate
            }
        } else if (!verify_target(def, ctx, target, hit->address, out)) {
            audit_miss(def, ctx, "decode_failed", ordered.size(), out.detail);
            return false;
        }
        out.status = ResolveStatus::Resolved;
        out.target_va = target;
        out.target_rva = target - ctx.module_base;
        copy_text(out.pattern, sizeof(out.pattern), hit->pattern);
        return true;
    }

    if (out.status == ResolveStatus::Internal || out.status == ResolveStatus::Resolved) {
        out.status = ResolveStatus::DecodeFailed;
        if (out.detail[0] == '\0') {
            set_detail(out.detail, sizeof(out.detail), "no candidate passed the read-only verifier");
        }
    }
    audit_miss(def, ctx, "decode_failed", ordered.size(), out.detail);
    return false;
}

uint32_t entry_count(void *self) {
    const auto *desc = static_cast<const ProviderDesc *>(self);
    return desc ? static_cast<uint32_t>(desc->entry_count) : 0;
}

bool entry_at(void *self, uint32_t index, EntryView *out) {
    const auto *desc = static_cast<const ProviderDesc *>(self);
    if (!desc || !out || index >= desc->entry_count) {
        return false;
    }
    *out = EntryView{};
    const auto &def = desc->entries[index];
    copy_text(out->owner, sizeof(out->owner), def.owner);
    copy_text(out->name, sizeof(out->name), def.name);
    copy_text(out->description, sizeof(out->description), def.description);
    out->platform_mask = def.platform_mask;
    out->definition_revision = def.definition_revision;
    out->client_only = def.client_only;
    return true;
}

bool read_record(const ProviderDesc *desc, const char *name, const char *file_path, const ContextView *ctx,
                 CacheRecord *out, bool explicit_file) {
    if (!out) {
        return false;
    }
    *out = CacheRecord{};
    const EntryDef *def = find_entry(desc, name, ctx ? ctx->platform : host_platform());
    if (!def) {
        out->status = CacheStatus::MissingEntry;
        return false;
    }
    const char *path = explicit_file ? file_path : (ctx ? ctx->cache_path : nullptr);
    const uint32_t platform = ctx ? ctx->platform : host_platform();
    char detail[kMaxDetailLen] = {};
    const auto status = cache_read_entry(path, platform, def->owner, def->name, out, detail, sizeof(detail));
    if (status != CacheStatus::Ok) {
        out->status = status;
        return false;
    }
    return true;
}

bool get_cached(void *self, const char *name, const ContextView *ctx, CacheRecord *out) {
    // No exception may cross the module boundary this table is called through.
    try {
        return read_record(static_cast<const ProviderDesc *>(self), name, nullptr, ctx, out, false);
    } catch (const std::exception &error) {
        if (out) {
            *out = CacheRecord{};
            out->status = CacheStatus::InvalidFile;
        }
        spdlog::error("[signature] get_cached({}) threw: {}", name ? name : "?", error.what());
        return false;
    } catch (...) {
        if (out) {
            *out = CacheRecord{};
            out->status = CacheStatus::InvalidFile;
        }
        spdlog::error("[signature] get_cached({}) threw an unknown exception", name ? name : "?");
        return false;
    }
}

bool extract_from_file(void *self, const char *name, const char *file_path, const ContextView *ctx,
                       CacheRecord *out) {
    try {
        return read_record(static_cast<const ProviderDesc *>(self), name, file_path, ctx, out, true);
    } catch (const std::exception &error) {
        if (out) {
            *out = CacheRecord{};
            out->status = CacheStatus::InvalidFile;
        }
        spdlog::error("[signature] extract_from_file({}) threw: {}", name ? name : "?", error.what());
        return false;
    } catch (...) {
        if (out) {
            *out = CacheRecord{};
            out->status = CacheStatus::InvalidFile;
        }
        return false;
    }
}

bool resolve_for_provider(const ProviderDesc *desc, const char *name, const ContextView *in_ctx,
                         ResolveReport *out) {
    if (!out) {
        return false;
    }
    *out = ResolveReport{};
    if (!desc || !in_ctx) {
        out->status = ResolveStatus::Internal;
        set_detail(out->detail, sizeof(out->detail), "provider or context missing");
        return false;
    }
    // Callers that are not the Manager (the macOS version probe, ad-hoc tools) may
    // pass a context without the module range; fill it from the loaded module so
    // the raw/selected RVAs are relative to the right base.
    ContextView ctx_view = *in_ctx;
    if (ctx_view.module_base == 0 && ctx_view.module_path && *ctx_view.module_path) {
        GumModule *module = gum_process_find_module_by_name(ctx_view.module_path);
        if (auto *range = module ? gum_module_get_range(module) : nullptr) {
            ctx_view.module_base = range->base_address;
            ctx_view.module_size = range->size;
        }
    }
    const ContextView *ctx = &ctx_view;
    const EntryDef *def = find_entry(desc, name, ctx->platform);
    if (!def) {
        out->status = ResolveStatus::Internal;
        set_detail(out->detail, sizeof(out->detail), "unknown signature name");
        return false;
    }
    fill_meta_impl(*def, *out);
    if (!entry_applicable(*def, *ctx)) {
        out->status = ResolveStatus::NotApplicable;
        set_detail(out->detail, sizeof(out->detail), "not applicable to this platform / client-server target");
        return false;
    }

    if (ctx->cache_path && *ctx->cache_path) {
        CacheRecord rec{};
        char why[kMaxDetailLen] = {};
        const auto status = cache_read_entry(ctx->cache_path, ctx->platform, def->owner, def->name, &rec, why,
                                             sizeof(why));
        out->cache_status = status;
        if (status == CacheStatus::Ok) {
            std::string rule_why;
            if (!cache_rules_match(*def, *ctx, rec, rule_why)) {
                out->cache_status = CacheStatus::Stale;
                spdlog::debug("[signature] cache stale for {}: {}", def->name, rule_why);
            } else {
                std::string cached_why;
                if (validate_cached(*def, *ctx, rec, *out, cached_why)) {
                    return true;
                }
                spdlog::debug("[signature] cache rejected for {}: {}", def->name, cached_why);
                if (out->cache_status == CacheStatus::Ok) {
                    out->cache_status = CacheStatus::Stale;
                }
            }
        }
    }
    return scan_entry_impl(*def, *ctx, *out);
}

bool resolve(void *self, const char *name, const ContextView *ctx, ResolveReport *out) {
    // No exception may cross the module boundary this table is called through.
    try {
        return resolve_for_provider(static_cast<const ProviderDesc *>(self), name, ctx, out);
    } catch (const std::exception &error) {
        if (out) {
            *out = ResolveReport{};
            out->status = ResolveStatus::Internal;
            set_detail(out->detail, sizeof(out->detail), std::string{"resolve threw: "} + error.what());
        }
        spdlog::error("[signature] resolve({}) threw: {}", name ? name : "?", error.what());
        return false;
    } catch (...) {
        if (out) {
            *out = ResolveReport{};
            out->status = ResolveStatus::Internal;
            set_detail(out->detail, sizeof(out->detail), "resolve threw an unknown exception");
        }
        return false;
    }
}

bool table_repair(void *self, const char *name, const ContextView *ctx, const char *failure,
                  ResolveReport *out) {
    const auto *desc = static_cast<const ProviderDesc *>(self);
    if (!out) {
        return false;
    }
    *out = ResolveReport{};
    const EntryDef *def = desc ? find_entry(desc, name, ctx ? ctx->platform : host_platform()) : nullptr;
    if (!def) {
        out->status = ResolveStatus::Internal;
        set_detail(out->detail, sizeof(out->detail), "unknown signature name");
        return false;
    }
    if (!repair_entry(*desc, *def, *ctx, failure, *out)) {
        out->repaired = 0;
        return false;
    }
    return true;
}

} // namespace

bool cache_identity_matches(const ContextView &ctx, const CacheRecord &rec, std::string &why) {
    const char *digest = ctx.module_digest ? ctx.module_digest : "";
    if (digest[0] != '\0' && std::strcmp(rec.module_digest, digest) != 0) {
        why = "cached module content digest differs from the target binary";
        return false;
    }
    const char *version = ctx.game_version ? ctx.game_version : "";
    if (version[0] != '\0' && rec.game_version[0] != '\0' && std::strcmp(rec.game_version, version) != 0) {
        why = "cached game version differs from the target";
        return false;
    }
    return true;
}

bool repair_entry(const ProviderDesc &desc, const EntryDef &def, const ContextView &ctx, const char *failure,
                  ResolveReport &out) {
    out = ResolveReport{};
    fill_meta_impl(def, out);
    if (!desc.repair) {
        out.status = ResolveStatus::DecodeFailed;
        set_detail(out.detail, sizeof(out.detail), "provider has no repair algorithm for this entry");
        return false;
    }
    ResolveReport candidate{};
    if (!desc.repair(def, ctx, failure ? failure : "", candidate)) {
        out = candidate;
        if (out.detail[0] == '\0') {
            set_detail(out.detail, sizeof(out.detail), "repair algorithm produced no candidate");
        }
        return false;
    }
    // A repair product only counts after the normal scan/verify path accepts it.
    ResolveReport verified{};
    if (!scan_entry_impl(def, ctx, verified)) {
        out = verified;
        out.repaired = 0;
        return false;
    }
    verified.repaired = 1;
    out = verified;
    return verified.status == ResolveStatus::Resolved;
}

bool module_sections_for(const ContextView &ctx, function_relocation::ModuleSections &out) {
    // Resolve the module first: ctx.module_path may be spelled with mixed
    // separators (tools build it from a CMake path + "/bin64/..."), and the
    // section loader matches on the module's own canonical path.
    GumModule *module = nullptr;
    if (ctx.module_path && *ctx.module_path) {
        module = gum_process_find_module_by_name(ctx.module_path);
    }
    if (module == nullptr) {
        module = gum_process_get_main_module();
    }
    const char *path = module ? gum_module_get_path(module) : nullptr;
    if (path == nullptr) {
        return false;
    }
    out = function_relocation::ModuleSections{};
    return function_relocation::get_module_sections(path, out);
}

bool make_provider(const ProviderDesc *desc, ProviderV1 *out) {
    if (out) {
        *out = ProviderV1{};
    }
    if (!desc || !out || !desc->owner || !*desc->owner || !desc->entries || desc->entry_count == 0) {
        return false;
    }
    const size_t owner_len = std::strlen(desc->owner);
    if (owner_len >= kMaxOwnerLen) {
        return false;
    }
    if (desc->prepare) {
        // The prepare hook fills generated patterns. It must run per provider
        // (a shared once_flag would only ever prepare the first one) and its
        // implementations are idempotent.
        static std::mutex prepare_mutex;
        std::lock_guard lock(prepare_mutex);
        desc->prepare();
    }
    for (size_t i = 0; i < desc->entry_count; ++i) {
        const auto &def = desc->entries[i];
        if (!def.name || !*def.name || !def.owner || !*def.owner) {
            return false;
        }
        if (std::strlen(def.name) >= kMaxNameLen) {
            return false;
        }
        if (std::strcmp(def.owner, desc->owner) != 0) {
            return false;
        }
        // "<owner>.<symbol>" — names must not follow the pattern they point at.
        if (std::strncmp(def.name, desc->owner, owner_len) != 0 || def.name[owner_len] != '.') {
            return false;
        }
        if (def.hits_policy < static_cast<int32_t>(HitsPolicy::Unique) ||
            def.hits_policy > static_cast<int32_t>(HitsPolicy::FilteredLowest)) {
            return false;
        }
        if (def.resolve_kind < static_cast<int32_t>(ResolveKind::RawOffset) ||
            def.resolve_kind > static_cast<int32_t>(ResolveKind::FdeEntry)) {
            return false;
        }
    }
    out->struct_size = sizeof(ProviderV1);
    out->interface_version = kProviderInterfaceVersion;
    out->self = const_cast<ProviderDesc *>(desc);
    out->entry_count = entry_count;
    out->entry_at = entry_at;
    out->get_cached = get_cached;
    out->extract_from_file = extract_from_file;
    out->resolve = resolve;
    out->repair = desc->repair ? table_repair : nullptr;
    return true;
}

} // namespace ds::sig
