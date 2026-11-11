#pragma once
// Plugin signature provider contract (POD, cross-DLL safe).
//
// A provider owns one owner's stable signature definitions ("names"), its
// read-only scan/verify implementation and the optional repair algorithm. The
// Injector's SignatureManager owns the only runtime registry, the target
// context and the unified result cache; tools enumerate the same providers
// through an explicit table (they never load plugin DLLs).
//
// Rules for every member of this header:
//   * POD only. No STL container, no std::string, no ownership transfer: the
//     receiver copies what it needs before the call returns.
//   * Every out-parameter is filled by the callee; borrowed char pointers only
//     in EntryView (static provider storage) and ContextView (caller storage).
//   * No exception may cross an interface boundary.
//   * Unsupported/inapplicable entries report a status instead of failing the
//     whole provider.

#include <cstddef>
#include <cstdint>

namespace ds::sig {

inline constexpr uint32_t kProviderInterfaceVersion = 1;

inline constexpr uint32_t kMaxPatternLen = 640;
inline constexpr uint32_t kMaxNameLen = 128;
inline constexpr uint32_t kMaxOwnerLen = 48;
inline constexpr uint32_t kMaxDetailLen = 256;
inline constexpr uint32_t kMaxDigestLen = 64;
inline constexpr uint32_t kMaxVersionLen = 64;
inline constexpr uint32_t kMaxHits = 8;
inline constexpr uint32_t kMaxCandidates = 8;

// Target platform, as a bit so one definition can list several. The value is
// the same "<system>-<arch>" spelling the Lua signature DB uses, mapped to a
// bit; the text is only used for cache sections and reports.
enum Platform : uint32_t {
    kPlatformNone = 0,
    kPlatformWindowsX64 = 1u << 0,
    kPlatformLinuxX64 = 1u << 1,
    kPlatformMacosX64 = 1u << 2,
    kPlatformMacosArm64 = 1u << 3,
    kPlatformAll = 0xFFFFFFFFu,
};

// Two platform masks name the same capability when they overlap.
inline constexpr bool masks_overlap(uint32_t a, uint32_t b) {
    return (a & b) != 0;
}

// Host target of THIS build, as a compile-time switch. A provider table only
// emits the definitions of the target it is compiled for — a Windows build
// carries no Linux/macOS pattern and vice versa — so neither the binary nor the
// runtime/cache table ever holds foreign-platform entries. `platform_mask` stays
// on every entry as the second, runtime-level check (a plugin DLL can be copied
// between trees) and as the cache-section key.
//
// Every supported target is 64-bit; 32-bit hosts are not built at all.
#if defined(_WIN32)
#  define DS_SIG_TARGET_WINDOWS_X64 1
#elif defined(__linux__)
#  define DS_SIG_TARGET_LINUX_X64 1
#elif defined(__APPLE__) && (defined(__aarch64__) || defined(__arm64__))
#  define DS_SIG_TARGET_MACOS_ARM64 1
#elif defined(__APPLE__)
#  define DS_SIG_TARGET_MACOS_X64 1
#endif

// Host platform of the build this TU was compiled for (single bit).
uint32_t host_platform();
// "<system>-<arch>" for a single-bit platform value ("windows-x64", …).
const char *platform_name(uint32_t platform);

// How a raw pattern hit becomes the address the consumer uses.
enum class ResolveKind : int32_t {
    RawOffset = 0, // hit + pattern_offset
    FdeEntry = 1,  // hit - pattern_offset resolved through the exact FDE range
};

// How raw hits across the candidate pattern list select the address.
enum class HitsPolicy : int32_t {
    // Exactly one hit across every candidate. More than one is ambiguous even
    // when a verifier could pick one: only Low/distrust- tolerant entries opt out.
    Unique = 0,
    // At least one hit; the lowest address wins (multi-hit tolerated).
    Lowest = 1,
    // Candidates are tried lowest-first and the first one whose verifier passes
    // wins. A verifier that rejects every candidate is a decode failure, not a miss.
    FilteredLowest = 2,
};

// Outcome of a resolve/extract request. NotApplicable/Unsupported are not
// failures: the entry simply does not exist for this target.
enum class ResolveStatus : int32_t {
    Resolved = 0,
    NotApplicable,   // client-only entry on a server, or platform not in the mask
    Unsupported,     // the provider has no implementation for this platform
    ModuleUnavailable,
    PatternMissing,  // zero raw hits
    PatternAmbiguous,// more than one raw hit where exactly one is required
    OffsetOutOfRange,// resolved address outside the module
    DecodeFailed,    // the read-only verifier rejected the address
    CacheMissing,    // check/update found no usable stored record for the entry
    Internal,
};

enum class CacheStatus : int32_t {
    NotRequested = 0,
    Ok,
    MissingFile,
    MissingEntry,
    InvalidFile,     // unparsable, wrong format_version, wrong section shape
    Stale,           // module digest / game version / definition revision differs
    OutOfRange,      // cached RVA outside the module
    Ambiguous,       // cached address no longer the only/expected hit
};

// Everything a provider needs to locate and validate its entries. Supplied by
// the caller (Manager at runtime, runner in tools).
struct ContextView {
    uint32_t struct_size = sizeof(ContextView);
    uint32_t platform = kPlatformNone; // single bit, see Platform
    int32_t is_client = 1;
    int32_t reserved = 0;
    const char *module_path = nullptr; // narrow path; null → main module
    uint64_t module_base = 0;
    uint64_t module_size = 0;
    const char *game_version = nullptr;  // null when the version file is absent
    const char *module_digest = nullptr; // content digest of the target binary
    const char *cache_path = nullptr;    // resolved plugin_signatures_*.json, may be null
};

// One provider entry, copied out of provider storage.
struct EntryView {
    char owner[kMaxOwnerLen] = {};
    char name[kMaxNameLen] = {};
    char description[kMaxDetailLen] = {};
    uint32_t platform_mask = kPlatformNone;
    int32_t definition_revision = 0;
    uint8_t client_only = 0;
    uint8_t reserved[3] = {};
};

// One entry as stored in the fixed cache. Produced by get_cached /
// extract_from_file and by resolve() on success (so create/update can persist
// exactly what was verified).
struct CacheRecord {
    CacheStatus status = CacheStatus::NotRequested;
    int32_t pattern_offset = 0;
    int32_t hits_policy = 0;
    int32_t resolve_kind = 0;
    int32_t definition_revision = 0;
    uint32_t platform_mask = kPlatformNone;
    uint8_t client_only = 0;
    uint8_t reserved[3] = {};
    uint32_t raw_hit_count = 0;
    uint64_t raw_hit_rvas[kMaxHits] = {};
    uint64_t target_rva = 0;
    char game_version[kMaxVersionLen] = {};
    char module_digest[kMaxDigestLen] = {};
    char pattern[kMaxPatternLen] = {};
};

struct ResolveReport {
    ResolveStatus status = ResolveStatus::Internal;
    CacheStatus cache_status = CacheStatus::NotRequested;
    int32_t pattern_offset = 0;
    int32_t hits_policy = 0;
    int32_t resolve_kind = 0;
    int32_t definition_revision = 0;
    uint32_t platform_mask = kPlatformNone;
    uint32_t raw_hit_count = 0;
    uint32_t hit_count = 0; // valid entries in raw_hit_rvas / target_rvas
    uint8_t client_only = 0;
    uint8_t from_cache = 0; // address came from a fully validated cache record
    uint8_t repaired = 0;   // produced by the optional repair path
    uint8_t reserved = 0;
    uint64_t target_va = 0;
    uint64_t target_rva = 0;
    uint64_t raw_hit_rvas[kMaxHits] = {};
    uint64_t target_rvas[kMaxHits] = {};
    char pattern[kMaxPatternLen] = {}; // winning pattern (candidate that matched)
    char detail[kMaxDetailLen] = {};
};

// Provider function table. struct_size/interface_version are checked before any
// call; a mismatch is a rejected registration, never a partially used provider.
struct ProviderV1 {
    uint32_t struct_size = sizeof(ProviderV1);
    uint32_t interface_version = kProviderInterfaceVersion;
    void *self = nullptr;

    // names()
    uint32_t (*entry_count)(void *self) = nullptr;
    bool (*entry_at)(void *self, uint32_t index, EntryView *out) = nullptr;

    // get_cached(): read-only lookup in ctx->cache_path. Never scans, repairs or
    // writes, and never reports an absolute address from a previous process.
    bool (*get_cached)(void *self, const char *name, const ContextView *ctx, CacheRecord *out) = nullptr;

    // extract_from_file(): same record, parsed from an explicit cache file.
    bool (*extract_from_file)(void *self, const char *name, const char *file_path, const ContextView *ctx,
                              CacheRecord *out) = nullptr;

    // Scan the target module read-only, apply the entry's selection/address rules
    // and run its verifier. No hook, no memory write, no cache mutation.
    bool (*resolve)(void *self, const char *name, const ContextView *ctx, ResolveReport *out) = nullptr;

    // Optional: re-derive a stale entry (create/update only; check never calls it).
    // The result must be a freshly scanned and verified address.
    bool (*repair)(void *self, const char *name, const ContextView *ctx, const char *failure,
                   ResolveReport *out) = nullptr;
};

} // namespace ds::sig
