#pragma once

#include <cstddef>

namespace ds::alloc {

    // One CRT export (Windows) or one imported symbol (ELF / Mach-O) the shim can
    // replace. `alias` names a second export in the same module that the primary
    // entry may tail-jump into: ucrtbase exposes `malloc -> _malloc_base`, and
    // FastHook follows native jumps, so both spellings must be offered.
    enum class SlotKind : unsigned char {
        Malloc,
        Calloc,
        Realloc,
        Free,
        Recalloc,
        Msize,
        Expand,
        AlignedMalloc,
        AlignedFree,
        AlignedRealloc,
        AlignedRecalloc,
        AlignedMsize,
        AlignedOffsetMalloc,
        AlignedOffsetRealloc,
        AlignedOffsetRecalloc,
        ReallocArray,
        PosixMemalign,
        AlignedAlloc,
        Memalign,
        Valloc,
        Strdup,
        Wcsdup,
    };

    struct SlotDesc {
        const char *name;
        const char *alias;// may be nullptr
        SlotKind kind;
        bool required;    // module coverage fails when this entry cannot be hooked
    };

    // Produces memory from the shim's own heap. Consumers/queries (free, realloc,
    // _msize, ...) are installed first: gum and FastHook allocate while installing,
    // so a producer must never be visible to a still-original consumer.
    constexpr bool produces_memory(SlotKind kind) noexcept {
        switch (kind) {
            case SlotKind::Malloc:
            case SlotKind::Calloc:
            case SlotKind::AlignedMalloc:
            case SlotKind::AlignedOffsetMalloc:
            case SlotKind::ReallocArray:
            case SlotKind::PosixMemalign:
            case SlotKind::AlignedAlloc:
            case SlotKind::Memalign:
            case SlotKind::Valloc:
            case SlotKind::Strdup:
            case SlotKind::Wcsdup:
                return true;
            default:
                return false;
        }
    }

    // Windows: msvcr90.dll / ucrtbase.dll exports. `_strdup` / `_wcsdup` / `??2` /
    // `??3` are deliberately absent: they allocate through these same entries
    // inside the CRT image, so hooking the entries covers them.
    inline constexpr SlotDesc kWindowsCrtSlots[] = {
            {"free", "_free_base", SlotKind::Free, true},
            {"realloc", "_realloc_base", SlotKind::Realloc, true},
            {"_recalloc", "_recalloc_base", SlotKind::Recalloc, true},
            {"_msize", "_msize_base", SlotKind::Msize, true},
            {"_expand", "_expand_base", SlotKind::Expand, false},
            {"_aligned_free", nullptr, SlotKind::AlignedFree, true},
            {"_aligned_realloc", nullptr, SlotKind::AlignedRealloc, false},
            {"_aligned_recalloc", nullptr, SlotKind::AlignedRecalloc, false},
            {"_aligned_msize", nullptr, SlotKind::AlignedMsize, false},
            {"_aligned_offset_realloc", nullptr, SlotKind::AlignedOffsetRealloc, false},
            {"_aligned_offset_recalloc", nullptr, SlotKind::AlignedOffsetRecalloc, false},
            {"malloc", "_malloc_base", SlotKind::Malloc, true},
            {"calloc", "_calloc_base", SlotKind::Calloc, true},
            {"_aligned_malloc", nullptr, SlotKind::AlignedMalloc, true},
            {"_aligned_offset_malloc", nullptr, SlotKind::AlignedOffsetMalloc, false},
    };

    // POSIX: imported symbol names. `strdup` is rewritten too so its block is an
    // owned pointer (mi_free handles it); every other entry is matched by name.
    inline constexpr SlotDesc kPosixSlots[] = {
            {"malloc", nullptr, SlotKind::Malloc, true},
            {"calloc", nullptr, SlotKind::Calloc, true},
            {"realloc", nullptr, SlotKind::Realloc, true},
            {"free", nullptr, SlotKind::Free, true},
            {"reallocarray", nullptr, SlotKind::ReallocArray, false},
            {"posix_memalign", nullptr, SlotKind::PosixMemalign, false},
            {"aligned_alloc", nullptr, SlotKind::AlignedAlloc, false},
            {"memalign", nullptr, SlotKind::Memalign, false},
            {"valloc", nullptr, SlotKind::Valloc, false},
            {"strdup", nullptr, SlotKind::Strdup, false},
    };

}// namespace ds::alloc
