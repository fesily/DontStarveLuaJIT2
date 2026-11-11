#pragma once
// Fixed-signature cache: <mod>/plugin_signatures_{client,server}.json.
//
// One document holds every platform section, exactly like the Lua DB
// (signatures_{client,server}.json, format v2) next to it: a run reads and
// rewrites only its own "<system>-<arch>" section. This file is separate from
// the Lua DB on purpose — the two have different keys, different address
// domains (Lua offsets are relative to the Lua module base) and different
// writers, and mixing them made one side's regeneration drop the other's
// entries.
//
// No global state lives here: the Injector's SignatureManager owns the single
// runtime registry, tools own nothing but the file they were pointed at.

#include "core/SignatureProvider.hpp"

#include <cstddef>
#include <string>

namespace ds::sig {

// Target identity stored once per platform section.
struct CacheFileIdentity {
    char game_version[kMaxVersionLen] = {};
    char module_digest[kMaxDigestLen] = {};
    uint64_t module_size = 0;
};

// FNV-1a-64 over the whole file, lowercase hex (16 chars). Empty on failure.
// Cheap enough to run once per process and strong enough to notice "the version
// text did not change but the binary did".
std::string module_content_digest(const char *path);

// Read one entry. `out->status` describes exactly why a lookup failed; anything
// other than CacheStatus::Ok must not be consumed as an address.
CacheStatus cache_read_entry(const char *file_path, uint32_t platform, const char *owner, const char *name,
                             CacheRecord *out, char *detail, size_t detail_cap);

struct CacheWriteEntry {
    const char *name = nullptr;
    const CacheRecord *record = nullptr;
};

// Replace one owner's entry set for `platform` and leave every other owner and
// platform section untouched. Holds an exclusive lock next to the file while
// writing so two processes cannot drop each other's sections. Returns false and
// fills `detail` when the file cannot be read/merged/written.
bool cache_write_owner(const char *file_path, uint32_t platform, const char *owner,
                       const CacheFileIdentity &identity, const CacheWriteEntry *entries, size_t count,
                       char *detail, size_t detail_cap);

} // namespace ds::sig
