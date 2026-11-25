#pragma once

#include "AllocTargets.hpp"

#include <cstddef>
#include <cstdint>
#include <wchar.h>

namespace ds::alloc {

    enum class Backend { None, WinCrtHook, ElfGot, MachO };

    struct Options {
        bool enabled = true;
        bool patch_all_modules = true;// Windows: also hook ucrtbase; POSIX: also scan non-main modules
        bool stats = false;           // own/foreign counters (never mi_option_show_stats)
    };

    struct Stats {
        uint64_t malloc_calls = 0;
        uint64_t free_own = 0;
        uint64_t free_foreign = 0;
        uint64_t realloc_foreign = 0;
    };

    // Original entries of one CRT provider (one module). A replacement installed
    // for provider K always falls back into K's own trampolines: handing a
    // UCRT block to msvcr90's free (or vice versa) corrupts the heap.
    struct ProviderOrig {
        void *(*malloc_fn)(size_t) = nullptr;
        void *(*calloc_fn)(size_t, size_t) = nullptr;
        void *(*realloc_fn)(void *, size_t) = nullptr;
        void (*free_fn)(void *) = nullptr;
        void *(*recalloc_fn)(void *, size_t, size_t) = nullptr;
        size_t (*msize_fn)(void *) = nullptr;
        void *(*expand_fn)(void *, size_t) = nullptr;
        void *(*aligned_malloc_fn)(size_t, size_t) = nullptr;
        void (*aligned_free_fn)(void *) = nullptr;
        void *(*aligned_realloc_fn)(void *, size_t, size_t) = nullptr;
        void *(*aligned_recalloc_fn)(void *, size_t, size_t, size_t) = nullptr;
        size_t (*aligned_msize_fn)(void *, size_t, size_t) = nullptr;
        void *(*aligned_offset_malloc_fn)(size_t, size_t, size_t) = nullptr;
        void *(*aligned_offset_realloc_fn)(void *, size_t, size_t, size_t) = nullptr;
        void *(*aligned_offset_recalloc_fn)(void *, size_t, size_t, size_t, size_t) = nullptr;
        void *(*reallocarray_fn)(void *, size_t, size_t) = nullptr;
        int (*posix_memalign_fn)(void **, size_t, size_t) = nullptr;
        void *(*aligned_alloc_fn)(size_t, size_t) = nullptr;
        void *(*memalign_fn)(size_t, size_t) = nullptr;
        void *(*valloc_fn)(size_t) = nullptr;
        char *(*strdup_fn)(const char *) = nullptr;
        wchar_t *(*wcsdup_fn)(const wchar_t *) = nullptr;

        const char *module = nullptr;// diagnostic name
        bool active = false;         // provider took over at least one entry
    };

    // msvcr90(+d), ucrtbase(+d); POSIX backends use index 0 for the C runtime.
    inline constexpr size_t kMaxProviders = 4;

    // Address of ProviderOrig's field for `kind`; the backends hand it to the hook
    // engine as the trampoline output, the tests use it to inject fakes.
    void **orig_slot(ProviderOrig &prov, SlotKind kind) noexcept;

    // Replacement entry for provider `provider` and `kind`, or nullptr when the
    // kind is not supported on this platform.
    void *shim_entry(size_t provider, SlotKind kind) noexcept;

    ProviderOrig &provider_slot(size_t idx) noexcept;// test seam

    bool install_early(const Options &opts) noexcept;
    bool installed() noexcept;
    const char *backend_name() noexcept;
    size_t patched_slot_count() noexcept;
    bool primary_target_patched() noexcept;
    // Windows: a debug CRT image is loaded, so the release-CRT-only shim refuses to
    // install (its block bookkeeping lives in the debug image, not in the allocator).
    bool skipped_debug_crt() noexcept;
    size_t failure_count() noexcept;
    Stats stats() noexcept;

    // Entry points keep their original implementation while shutting down: the
    // CRT is still alive at DLL_PROCESS_DETACH, the static mimalloc image is not.
    void set_shutting_down() noexcept;
    bool shutting_down() noexcept;

    // phase 0 accessors: no allocation, no logging, no InjectorCtx.
    bool read_env_switch() noexcept;// DS_ALLOC_SHIM: Windows unset => true; POSIX opt-in only without the preload stub; off/0/no => false
    bool read_env_stats() noexcept; // DS_ALLOC_SHIM_STATS=1

    namespace detail {
        void set_backend(Backend backend) noexcept;
        void note_patched(size_t count) noexcept;
        void note_primary_target() noexcept;
        void note_failure() noexcept;
        void set_stats_enabled(bool enabled) noexcept;// test seam (never installs hooks)
        void note_skipped_debug_crt() noexcept;

#ifdef _WIN32
        bool install_win_crt_hooks(const Options &opts);
#else
        bool install_platform_hooks(const Options &opts);
        void rescan_modules() noexcept;// Task 6: later dlopen()ed images
#endif
    }// namespace detail

}// namespace ds::alloc
