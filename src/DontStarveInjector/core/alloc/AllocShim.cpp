#include "AllocShim.hpp"

#include <mimalloc.h>

#include <atomic>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

namespace ds::alloc {
    namespace {

        struct State {
            std::atomic<bool> attempted{false};
            std::atomic<bool> installed{false};
            std::atomic<bool> stats_on{false};
            std::atomic<bool> shutting_down{false};
            std::atomic<Backend> backend{Backend::None};
            std::atomic<size_t> patched{0};
            std::atomic<size_t> failures{0};
            std::atomic<bool> primary{false};
            std::atomic<bool> debug_crt{false};
            std::atomic<uint64_t> malloc_calls{0};
            std::atomic<uint64_t> free_own{0};
            std::atomic<uint64_t> free_foreign{0};
            std::atomic<uint64_t> realloc_foreign{0};
        };

        State &state() {
            static auto *instance = new State;
            return *instance;
        }

        // Fixed capacity: phase 0 must not allocate a container, and a provider is
        // never added after install (every module's entries resolve at install time
        // or, for POSIX, at the dlopen callback).
        ProviderOrig g_providers[kMaxProviders];

        void count_malloc() noexcept {
            if (state().stats_on.load(std::memory_order_relaxed)) {
                state().malloc_calls.fetch_add(1, std::memory_order_relaxed);
            }
        }

        void count_free(bool own) noexcept {
            if (state().stats_on.load(std::memory_order_relaxed)) {
                (own ? state().free_own : state().free_foreign).fetch_add(1, std::memory_order_relaxed);
            }
        }

        void count_realloc_foreign() noexcept {
            if (state().stats_on.load(std::memory_order_relaxed)) {
                state().realloc_foreign.fetch_add(1, std::memory_order_relaxed);
            }
        }

        bool can_release() noexcept {
            return !state().shutting_down.load(std::memory_order_relaxed);
        }

        template<size_t K>
        struct ShimSet {
            static ProviderOrig &orig() noexcept { return g_providers[K]; }

            // --- producers ---------------------------------------------------
            static void *malloc_(size_t n) noexcept {
                count_malloc();
                return mi_malloc(n);
            }

            static void *calloc_(size_t count, size_t size) noexcept {
                count_malloc();
                return mi_calloc(count, size);
            }

            static void *realloc_(void *p, size_t n) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_realloc(nullptr, n);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().realloc_fn;
                    return fn != nullptr ? fn(p, n) : nullptr;
                }
                if (n == 0) {// msvcr90/ucrt/glibc all free and return NULL
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_realloc(p, n);
            }

            static void *recalloc_(void *p, size_t count, size_t size) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_recalloc(nullptr, count, size);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().recalloc_fn;
                    return fn != nullptr ? fn(p, count, size) : nullptr;
                }
                if (count == 0 || size == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_recalloc(p, count, size);
            }

            static void *expand_(void *p, size_t n) noexcept {
                if (p == nullptr) return nullptr;// _expand(NULL, ...) is invalid in the CRT too
                if (!mi_is_in_heap_region(p)) {
                    const auto fn = orig().expand_fn;
                    return fn != nullptr ? fn(p, n) : nullptr;
                }
                if (n == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_expand(p, n);
            }

            static void *aligned_malloc_(size_t n, size_t alignment) noexcept {
                count_malloc();
                return mi_malloc_aligned(n, alignment);
            }

            static void *aligned_offset_malloc_(size_t n, size_t alignment, size_t offset) noexcept {
                count_malloc();
                return mi_malloc_aligned_at(n, alignment, offset);
            }

            static void *aligned_realloc_(void *p, size_t n, size_t alignment) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_realloc_aligned(nullptr, n, alignment);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().aligned_realloc_fn;
                    return fn != nullptr ? fn(p, n, alignment) : nullptr;
                }
                if (n == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_realloc_aligned(p, n, alignment);
            }

            static void *aligned_recalloc_(void *p, size_t count, size_t size, size_t alignment) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_recalloc_aligned(nullptr, count, size, alignment);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().aligned_recalloc_fn;
                    return fn != nullptr ? fn(p, count, size, alignment) : nullptr;
                }
                if (count == 0 || size == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_recalloc_aligned(p, count, size, alignment);
            }

            static void *aligned_offset_realloc_(void *p, size_t n, size_t alignment, size_t offset) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_realloc_aligned_at(nullptr, n, alignment, offset);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().aligned_offset_realloc_fn;
                    return fn != nullptr ? fn(p, n, alignment, offset) : nullptr;
                }
                if (n == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_realloc_aligned_at(p, n, alignment, offset);
            }

            static void *aligned_offset_recalloc_(void *p, size_t count, size_t size, size_t alignment, size_t offset) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_recalloc_aligned_at(nullptr, count, size, alignment, offset);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().aligned_offset_recalloc_fn;
                    return fn != nullptr ? fn(p, count, size, alignment, offset) : nullptr;
                }
                if (count == 0 || size == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_recalloc_aligned_at(p, count, size, alignment, offset);
            }

            static void *reallocarray_(void *p, size_t count, size_t size) noexcept {
                if (p == nullptr) {
                    count_malloc();
                    return mi_reallocarray(nullptr, count, size);
                }
                if (!mi_is_in_heap_region(p)) {
                    count_realloc_foreign();
                    const auto fn = orig().reallocarray_fn;
                    return fn != nullptr ? fn(p, count, size) : nullptr;
                }
                if (count == 0 || size == 0) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return nullptr;
                }
                return mi_reallocarray(p, count, size);
            }

            static int posix_memalign_(void **out, size_t alignment, size_t n) noexcept {
                count_malloc();
                return mi_posix_memalign(out, alignment, n);
            }

            static void *aligned_alloc_(size_t alignment, size_t n) noexcept {
                count_malloc();
                return mi_aligned_alloc(alignment, n);
            }

#ifndef _WIN32
            static void *memalign_(size_t alignment, size_t n) noexcept {
                count_malloc();
                return mi_malloc_aligned(n, alignment);
            }

            static void *valloc_(size_t n) noexcept {
                static const size_t page = [] {
                    const long value = sysconf(_SC_PAGESIZE);
                    return value > 0 ? static_cast<size_t>(value) : static_cast<size_t>(4096);
                }();
                count_malloc();
                return mi_malloc_aligned(n, page);
            }
#endif

            static char *strdup_(const char *s) noexcept {
                count_malloc();
                return mi_strdup(s);
            }

#ifdef _WIN32
            static wchar_t *wcsdup_(const wchar_t *s) noexcept {
                count_malloc();
                return reinterpret_cast<wchar_t *>(mi_wcsdup(reinterpret_cast<const unsigned short *>(s)));
            }
#endif

            // --- consumers / queries -----------------------------------------
            static void free_(void *p) noexcept {
                if (p == nullptr) return;
                if (mi_is_in_heap_region(p)) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return;
                }
                count_free(false);
                const auto fn = orig().free_fn;
                if (fn != nullptr) fn(p);
            }

            // _aligned_free carries its own block header: a foreign aligned block
            // must never reach the plain CRT free.
            static void aligned_free_(void *p) noexcept {
                if (p == nullptr) return;
                if (mi_is_in_heap_region(p)) {
                    count_free(true);
                    if (can_release()) mi_free(p);
                    return;
                }
                count_free(false);
                const auto fn = orig().aligned_free_fn;
                if (fn != nullptr) fn(p);
            }

            static size_t msize_(void *p) noexcept {
                if (p == nullptr) return 0;
                if (mi_is_in_heap_region(p)) return mi_usable_size(p);
                const auto fn = orig().msize_fn;
                return fn != nullptr ? fn(p) : 0;
            }

            static size_t aligned_msize_(void *p, size_t alignment, size_t offset) noexcept {
                if (p == nullptr) return 0;
                if (mi_is_in_heap_region(p)) return mi_usable_size(p);
                const auto fn = orig().aligned_msize_fn;
                return fn != nullptr ? fn(p, alignment, offset) : 0;
            }

            static void *entry(SlotKind kind) noexcept {
                switch (kind) {
                    case SlotKind::Malloc: return reinterpret_cast<void *>(&malloc_);
                    case SlotKind::Calloc: return reinterpret_cast<void *>(&calloc_);
                    case SlotKind::Realloc: return reinterpret_cast<void *>(&realloc_);
                    case SlotKind::Free: return reinterpret_cast<void *>(&free_);
                    case SlotKind::Recalloc: return reinterpret_cast<void *>(&recalloc_);
                    case SlotKind::Msize: return reinterpret_cast<void *>(&msize_);
                    case SlotKind::Expand: return reinterpret_cast<void *>(&expand_);
                    case SlotKind::AlignedMalloc: return reinterpret_cast<void *>(&aligned_malloc_);
                    case SlotKind::AlignedFree: return reinterpret_cast<void *>(&aligned_free_);
                    case SlotKind::AlignedRealloc: return reinterpret_cast<void *>(&aligned_realloc_);
                    case SlotKind::AlignedRecalloc: return reinterpret_cast<void *>(&aligned_recalloc_);
                    case SlotKind::AlignedMsize: return reinterpret_cast<void *>(&aligned_msize_);
                    case SlotKind::AlignedOffsetMalloc: return reinterpret_cast<void *>(&aligned_offset_malloc_);
                    case SlotKind::AlignedOffsetRealloc: return reinterpret_cast<void *>(&aligned_offset_realloc_);
                    case SlotKind::AlignedOffsetRecalloc: return reinterpret_cast<void *>(&aligned_offset_recalloc_);
                    case SlotKind::ReallocArray: return reinterpret_cast<void *>(&reallocarray_);
                    case SlotKind::PosixMemalign: return reinterpret_cast<void *>(&posix_memalign_);
                    case SlotKind::AlignedAlloc: return reinterpret_cast<void *>(&aligned_alloc_);
#ifndef _WIN32
                    case SlotKind::Memalign: return reinterpret_cast<void *>(&memalign_);
                    case SlotKind::Valloc: return reinterpret_cast<void *>(&valloc_);
#else
                    case SlotKind::Memalign:
                    case SlotKind::Valloc: return nullptr;
#endif
                    case SlotKind::Strdup: return reinterpret_cast<void *>(&strdup_);
#ifdef _WIN32
                    case SlotKind::Wcsdup: return reinterpret_cast<void *>(&wcsdup_);
#else
                    case SlotKind::Wcsdup: return nullptr;
#endif
                }
                return nullptr;
            }
        };

        bool ascii_equal_ignore_case(const char *value, const char *expected) noexcept {
            for (;; ++value, ++expected) {
                if (*expected == '\0') return *value == '\0';
                if (*value == '\0') return false;
                char left = *value;
                if (left >= 'A' && left <= 'Z') left = static_cast<char>(left - 'A' + 'a');
                if (left != *expected) return false;
            }
        }

        bool env_disables(const char *value) noexcept {
            return ascii_equal_ignore_case(value, "off") ||
                   ascii_equal_ignore_case(value, "0") ||
                   ascii_equal_ignore_case(value, "no");
        }

    }// namespace

    void **orig_slot(ProviderOrig &prov, SlotKind kind) noexcept {
        switch (kind) {
            case SlotKind::Malloc: return reinterpret_cast<void **>(&prov.malloc_fn);
            case SlotKind::Calloc: return reinterpret_cast<void **>(&prov.calloc_fn);
            case SlotKind::Realloc: return reinterpret_cast<void **>(&prov.realloc_fn);
            case SlotKind::Free: return reinterpret_cast<void **>(&prov.free_fn);
            case SlotKind::Recalloc: return reinterpret_cast<void **>(&prov.recalloc_fn);
            case SlotKind::Msize: return reinterpret_cast<void **>(&prov.msize_fn);
            case SlotKind::Expand: return reinterpret_cast<void **>(&prov.expand_fn);
            case SlotKind::AlignedMalloc: return reinterpret_cast<void **>(&prov.aligned_malloc_fn);
            case SlotKind::AlignedFree: return reinterpret_cast<void **>(&prov.aligned_free_fn);
            case SlotKind::AlignedRealloc: return reinterpret_cast<void **>(&prov.aligned_realloc_fn);
            case SlotKind::AlignedRecalloc: return reinterpret_cast<void **>(&prov.aligned_recalloc_fn);
            case SlotKind::AlignedMsize: return reinterpret_cast<void **>(&prov.aligned_msize_fn);
            case SlotKind::AlignedOffsetMalloc: return reinterpret_cast<void **>(&prov.aligned_offset_malloc_fn);
            case SlotKind::AlignedOffsetRealloc: return reinterpret_cast<void **>(&prov.aligned_offset_realloc_fn);
            case SlotKind::AlignedOffsetRecalloc: return reinterpret_cast<void **>(&prov.aligned_offset_recalloc_fn);
            case SlotKind::ReallocArray: return reinterpret_cast<void **>(&prov.reallocarray_fn);
            case SlotKind::PosixMemalign: return reinterpret_cast<void **>(&prov.posix_memalign_fn);
            case SlotKind::AlignedAlloc: return reinterpret_cast<void **>(&prov.aligned_alloc_fn);
            case SlotKind::Memalign: return reinterpret_cast<void **>(&prov.memalign_fn);
            case SlotKind::Valloc: return reinterpret_cast<void **>(&prov.valloc_fn);
            case SlotKind::Strdup: return reinterpret_cast<void **>(&prov.strdup_fn);
            case SlotKind::Wcsdup: return reinterpret_cast<void **>(&prov.wcsdup_fn);
        }
        return nullptr;
    }

    void *shim_entry(size_t provider, SlotKind kind) noexcept {
        switch (provider) {
            case 0: return ShimSet<0>::entry(kind);
            case 1: return ShimSet<1>::entry(kind);
            case 2: return ShimSet<2>::entry(kind);
            case 3: return ShimSet<3>::entry(kind);
            default: return nullptr;
        }
    }

    ProviderOrig &provider_slot(size_t idx) noexcept {
        static ProviderOrig overflow{};
        return idx < kMaxProviders ? g_providers[idx] : overflow;
    }

    bool install_early(const Options &opts) noexcept {
        auto &s = state();
        bool expected = false;
        if (!s.attempted.compare_exchange_strong(expected, true)) {
            return s.installed.load(std::memory_order_acquire);
        }
        s.stats_on.store(opts.stats, std::memory_order_relaxed);
        if (!opts.enabled) {
            s.backend.store(Backend::None, std::memory_order_relaxed);
            return true;
        }
        bool ok = false;
#ifdef _WIN32
        ok = detail::install_win_crt_hooks(opts);
#else
        ok = detail::install_platform_hooks(opts);
#endif
        s.installed.store(ok, std::memory_order_release);
        return ok;
    }

    bool installed() noexcept {
        return state().installed.load(std::memory_order_acquire);
    }

    const char *backend_name() noexcept {
        switch (state().backend.load(std::memory_order_relaxed)) {
            case Backend::WinCrtHook: return "win-crt-hook";
            case Backend::ElfGot: return "elf-got";
            case Backend::MachO: return "macho-got";
            case Backend::None: return "none";
        }
        return "none";
    }

    size_t patched_slot_count() noexcept {
        return state().patched.load(std::memory_order_relaxed);
    }

    bool primary_target_patched() noexcept {
        return state().primary.load(std::memory_order_relaxed);
    }

    bool skipped_debug_crt() noexcept {
        return state().debug_crt.load(std::memory_order_relaxed);
    }

    size_t failure_count() noexcept {
        return state().failures.load(std::memory_order_relaxed);
    }

    Stats stats() noexcept {
        auto &s = state();
        Stats out{};
        out.malloc_calls = s.malloc_calls.load(std::memory_order_relaxed);
        out.free_own = s.free_own.load(std::memory_order_relaxed);
        out.free_foreign = s.free_foreign.load(std::memory_order_relaxed);
        out.realloc_foreign = s.realloc_foreign.load(std::memory_order_relaxed);
        return out;
    }

    void set_shutting_down() noexcept {
        state().shutting_down.store(true, std::memory_order_release);
    }

    bool shutting_down() noexcept {
        return state().shutting_down.load(std::memory_order_acquire);
    }

    bool read_env_switch() noexcept {
#ifdef _WIN32
        char value[16];
        const DWORD written = GetEnvironmentVariableA("DS_ALLOC_SHIM", value, sizeof(value));
        if (written == 0 || written >= sizeof(value)) return true;
        return !env_disables(value);
#else
        const char *value = getenv("DS_ALLOC_SHIM");
        if (value == nullptr || value[0] == '\0' || env_disables(value)) return false;
        // The POSIX stub preloads the MI_OVERRIDE=ON archive, so malloc/free
        // already resolve to mimalloc before the real Injector is dlopen()ed.
        // Installing the ELF GOT shim on top would create a second heap.
        return dlsym(RTLD_DEFAULT, "ds_stub_alloc_override") == nullptr;
#endif
    }

    bool read_env_stats() noexcept {
#ifdef _WIN32
        char value[8];
        const DWORD written = GetEnvironmentVariableA("DS_ALLOC_SHIM_STATS", value, sizeof(value));
        return written == 1 && value[0] == '1';
#else
        const char *value = getenv("DS_ALLOC_SHIM_STATS");
        return value != nullptr && value[0] == '1' && value[1] == '\0';
#endif
    }

    namespace detail {
        void set_backend(Backend backend) noexcept {
            state().backend.store(backend, std::memory_order_relaxed);
        }

        void note_patched(size_t count) noexcept {
            state().patched.fetch_add(count, std::memory_order_relaxed);
        }

        void note_primary_target() noexcept {
            state().primary.store(true, std::memory_order_relaxed);
        }

        void note_failure() noexcept {
            state().failures.fetch_add(1, std::memory_order_relaxed);
        }

        void note_skipped_debug_crt() noexcept {
            state().debug_crt.store(true, std::memory_order_relaxed);
        }

        void set_stats_enabled(bool enabled) noexcept {
            state().stats_on.store(enabled, std::memory_order_relaxed);
        }
    }// namespace detail

}// namespace ds::alloc
