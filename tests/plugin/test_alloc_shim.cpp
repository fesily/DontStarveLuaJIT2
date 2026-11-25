#include "core/alloc/AllocShim.hpp"

#include <doctest/doctest.h>
#include <mimalloc.h>

#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <malloc.h>
#endif

namespace {

    using FreeFn = void (*)(void *);
    using ReallocFn = void *(*)(void *, size_t);
    using RecallocFn = void *(*)(void *, size_t, size_t);
    using MsizeFn = size_t (*)(void *);
    using ExpandFn = void *(*)(void *, size_t);
    using AlignedFreeFn = void (*)(void *);

    void *crt_malloc(size_t size) {
        return std::malloc(size);
    }

    void crt_free(void *p) {
        std::free(p);
    }

    void *crt_realloc(void *p, size_t size) {
        return std::realloc(p, size);
    }

    void *crt_aligned_malloc(size_t size, size_t alignment) {
#ifdef _WIN32
        return _aligned_malloc(size, alignment);
#else
        void *p = nullptr;
        if (posix_memalign(&p, alignment, size) != 0) return nullptr;
        return p;
#endif
    }

    void crt_aligned_free(void *p) {
#ifdef _WIN32
        _aligned_free(p);
#else
        std::free(p);
#endif
    }

    // Records every call so a test can prove which provider fallback ran.
    struct Probe {
        int free_calls = 0;
        int realloc_calls = 0;
        int aligned_free_calls = 0;
    };

    Probe g_probe_plain;
    Probe g_probe_aligned;

    void probe_free(void *p) {
        ++g_probe_plain.free_calls;
        std::free(p);
    }

    void *probe_realloc(void *p, size_t size) {
        ++g_probe_plain.realloc_calls;
        return std::realloc(p, size);
    }

    void probe_aligned_free(void *p) {
        ++g_probe_aligned.aligned_free_calls;
        crt_aligned_free(p);
    }

    size_t probe_msize(void *) {
        return 4242;
    }

    void *probe_expand(void *, size_t) {
        return nullptr;
    }

    void *probe_recalloc(void *p, size_t count, size_t size) {
        crt_free(p);
        return crt_malloc(count * size);
    }

    template<typename Fn>
    Fn entry(size_t provider, ds::alloc::SlotKind kind) {
        const auto raw = ds::alloc::shim_entry(provider, kind);
        REQUIRE_MESSAGE(raw != nullptr, "shim entry exists for this kind");
        return reinterpret_cast<Fn>(raw);
    }

    ds::alloc::Stats baseline() {
        return ds::alloc::stats();
    }

    void reset_providers() {
        for (size_t i = 0; i < ds::alloc::kMaxProviders; ++i) {
            auto &prov = ds::alloc::provider_slot(i);
            prov = ds::alloc::ProviderOrig{};
        }
        g_probe_plain = Probe{};
        g_probe_aligned = Probe{};
    }

}// namespace

TEST_CASE("alloc_shim/null free is inert") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    const auto before = baseline();
    entry<FreeFn>(0, ds::alloc::SlotKind::Free)(nullptr);
    entry<FreeFn>(1, ds::alloc::SlotKind::Free)(nullptr);
    entry<AlignedFreeFn>(1, ds::alloc::SlotKind::AlignedFree)(nullptr);
    const auto after = baseline();
    CHECK_EQ(after.free_own, before.free_own);
    CHECK_EQ(after.free_foreign, before.free_foreign);
}

TEST_CASE("alloc_shim/own blocks are released by mimalloc") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    // A provider with no fallbacks: an own block must never reach it.
    const auto before = baseline();
    void *p = mi_malloc(32);
    REQUIRE_NE(p, nullptr);
    entry<FreeFn>(0, ds::alloc::SlotKind::Free)(p);
    const auto after = baseline();
    CHECK_EQ(after.free_own, before.free_own + 1);
    CHECK_EQ(after.free_foreign, before.free_foreign);
    CHECK_EQ(g_probe_plain.free_calls, 0);
}

TEST_CASE("alloc_shim/foreign blocks fall back to their own provider") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    ds::alloc::provider_slot(1).free_fn = &probe_free;
    ds::alloc::provider_slot(1).realloc_fn = &probe_realloc;

    const auto before = baseline();
    void *p = crt_malloc(24);
    REQUIRE_NE(p, nullptr);
    entry<FreeFn>(1, ds::alloc::SlotKind::Free)(p);
    CHECK_EQ(g_probe_plain.free_calls, 1);

    void *q = crt_malloc(16);
    REQUIRE_NE(q, nullptr);
    void *grown = entry<ReallocFn>(1, ds::alloc::SlotKind::Realloc)(q, 128);
    CHECK_EQ(g_probe_plain.realloc_calls, 1);
    REQUIRE_NE(grown, nullptr);
    crt_free(grown);

    const auto after = baseline();
    CHECK_EQ(after.free_foreign, before.free_foreign + 1);
    CHECK_EQ(after.realloc_foreign, before.realloc_foreign + 1);
    CHECK_EQ(after.free_own, before.free_own);
}

TEST_CASE("alloc_shim/zero-size realloc frees and returns null") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    ds::alloc::provider_slot(2).realloc_fn = &crt_realloc;

    void *own = mi_malloc(64);
    REQUIRE_NE(own, nullptr);
    CHECK_EQ(entry<ReallocFn>(0, ds::alloc::SlotKind::Realloc)(own, 0), nullptr);

    void *foreign = crt_malloc(64);
    REQUIRE_NE(foreign, nullptr);
    CHECK_EQ(entry<ReallocFn>(2, ds::alloc::SlotKind::Realloc)(foreign, 0), nullptr);
}

TEST_CASE("alloc_shim/malloc and calloc of zero are allocatable") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    void *empty = entry<void *(*)(size_t)>(0, ds::alloc::SlotKind::Malloc)(0);
    REQUIRE_NE(empty, nullptr);
    entry<FreeFn>(0, ds::alloc::SlotKind::Free)(empty);

    void *zeros = entry<void *(*)(size_t, size_t)>(0, ds::alloc::SlotKind::Calloc)(0, 16);
    REQUIRE_NE(zeros, nullptr);
    entry<FreeFn>(0, ds::alloc::SlotKind::Free)(zeros);
}

TEST_CASE("alloc_shim/aligned foreign blocks use the aligned fallback") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    ds::alloc::provider_slot(3).aligned_free_fn = &probe_aligned_free;
    ds::alloc::provider_slot(3).free_fn = &probe_free;

    void *own = mi_malloc_aligned(64, 64);
    REQUIRE_NE(own, nullptr);
    entry<AlignedFreeFn>(3, ds::alloc::SlotKind::AlignedFree)(own);
    CHECK_EQ(g_probe_aligned.aligned_free_calls, 0);
    CHECK_EQ(g_probe_plain.free_calls, 0);

    void *foreign = crt_aligned_malloc(64, 64);
    REQUIRE_NE(foreign, nullptr);
    entry<AlignedFreeFn>(3, ds::alloc::SlotKind::AlignedFree)(foreign);
    CHECK_EQ(g_probe_aligned.aligned_free_calls, 1);
    CHECK_EQ(g_probe_plain.free_calls, 0);
}

TEST_CASE("alloc_shim/msize and expand dispatch by ownership") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    ds::alloc::provider_slot(1).msize_fn = &probe_msize;
    ds::alloc::provider_slot(1).expand_fn = &probe_expand;

    void *own = mi_malloc(64);
    REQUIRE_NE(own, nullptr);
    CHECK_GE(entry<MsizeFn>(1, ds::alloc::SlotKind::Msize)(own), 64);
    // mi_expand refuses every block when MI_PADDING is on (Debug builds), so the
    // expectation is the allocator's own answer rather than a hard-coded success.
    CHECK_EQ(entry<ExpandFn>(1, ds::alloc::SlotKind::Expand)(own, 32), mi_expand(own, 32));
    entry<FreeFn>(0, ds::alloc::SlotKind::Free)(own);

    void *foreign = crt_malloc(32);
    REQUIRE_NE(foreign, nullptr);
    CHECK_EQ(entry<MsizeFn>(1, ds::alloc::SlotKind::Msize)(foreign), 4242);
    CHECK_EQ(entry<ExpandFn>(1, ds::alloc::SlotKind::Expand)(foreign, 8), nullptr);
    crt_free(foreign);
}

TEST_CASE("alloc_shim/recalloc dispatches by ownership") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    ds::alloc::provider_slot(2).recalloc_fn = &probe_recalloc;

    void *zeros = entry<RecallocFn>(2, ds::alloc::SlotKind::Recalloc)(nullptr, 4, 8);
    REQUIRE_NE(zeros, nullptr);
    const auto *bytes = static_cast<const unsigned char *>(zeros);
    for (size_t i = 0; i < 32; ++i) CHECK_EQ(bytes[i], 0);// zero-initialised like calloc
    entry<FreeFn>(0, ds::alloc::SlotKind::Free)(zeros);

    void *foreign = crt_malloc(8);
    REQUIRE_NE(foreign, nullptr);
    void *grown = entry<RecallocFn>(2, ds::alloc::SlotKind::Recalloc)(foreign, 2, 16);
    REQUIRE_NE(grown, nullptr);
    crt_free(grown);
}

TEST_CASE("alloc_shim/missing fallbacks are inert") {
    reset_providers();
    ds::alloc::detail::set_stats_enabled(true);
    void *foreign = crt_malloc(16);
    REQUIRE_NE(foreign, nullptr);
    entry<FreeFn>(3, ds::alloc::SlotKind::Free)(foreign);// no fallback installed: must not crash
    crt_free(foreign);
    CHECK_EQ(entry<MsizeFn>(3, ds::alloc::SlotKind::Msize)(foreign), 0);
}

TEST_CASE("alloc_shim/platform-specific entries") {
    CHECK_NE(ds::alloc::shim_entry(0, ds::alloc::SlotKind::Malloc), nullptr);
    CHECK_NE(ds::alloc::shim_entry(0, ds::alloc::SlotKind::Free), nullptr);
#ifdef _WIN32
    CHECK_NE(ds::alloc::shim_entry(0, ds::alloc::SlotKind::Wcsdup), nullptr);
#else
    CHECK_EQ(ds::alloc::shim_entry(0, ds::alloc::SlotKind::Wcsdup), nullptr);
    CHECK_NE(ds::alloc::shim_entry(0, ds::alloc::SlotKind::Valloc), nullptr);
#endif
}
