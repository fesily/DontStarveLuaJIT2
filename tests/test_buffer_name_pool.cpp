#include "BufferNamePool.hpp"

#include <cassert>
#include <cstdio>
#include <vector>

static constexpr uint32_t TARGET_ARRAY   = 0x8892u;
static constexpr uint32_t TARGET_ELEMENT = 0x8893u;
static constexpr uint32_t USAGE_STREAM   = 10u;

static std::vector<uint32_t> g_deleted;

static void mockDeleteBuffers(uint32_t count, const uint32_t* names) {
    for (uint32_t i = 0; i < count; ++i)
        g_deleted.push_back(names[i]);
}

static void test_acquire_miss() {
    BufferNamePool pool;
    assert(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128) == 0);
    assert(pool.stats().misses == 1);
    assert(pool.stats().hits == 0);
    printf("PASS: test_acquire_miss\n");
}

static void test_release_acquire_roundtrip() {
    BufferNamePool pool;
    assert(pool.release(42u, TARGET_ARRAY, USAGE_STREAM, 128));
    assert(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128) == 42u);
    assert(pool.stats().hits == 1);
    assert(pool.stats().deleteSaved == 1);
    assert(pool.stats().genSaved == 1);
    printf("PASS: test_release_acquire_roundtrip\n");
}

static void test_per_bucket_overflow() {
    BufferNamePool pool;
    for (uint32_t i = 1; i <= 32; ++i)
        assert(pool.release(i, TARGET_ARRAY, USAGE_STREAM, 128));

    assert(!pool.release(100u, TARGET_ARRAY, USAGE_STREAM, 128));
    assert(pool.stats().evictions >= 1);
    printf("PASS: test_per_bucket_overflow\n");
}

static void test_global_overflow() {
    BufferNamePool pool;
    const uint32_t bucketSizes[] = {64, 128, 256, 512, 1024, 2048, 4096, 8192};
    uint32_t name = 1;
    for (int b = 0; b < 8; ++b) {
        for (int i = 0; i < 32; ++i, ++name)
            assert(pool.release(name, TARGET_ARRAY, USAGE_STREAM, bucketSizes[b]));
    }
    assert(pool.totalPooled() == 256);
    assert(!pool.release(9999u, TARGET_ARRAY, USAGE_STREAM, 64u));
    printf("PASS: test_global_overflow\n");
}

static void test_bytes_budget_overflow() {
    BufferNamePool pool;
    const uint32_t oneMB = 1024u * 1024u;
    for (uint32_t i = 1; i <= 16; ++i)
        assert(pool.release(i, TARGET_ARRAY, USAGE_STREAM, oneMB));

    assert(pool.totalBytes() == 16u * 1024u * 1024u);
    assert(!pool.release(100u, TARGET_ARRAY, USAGE_STREAM, oneMB));
    printf("PASS: test_bytes_budget_overflow\n");
}

static void test_drain_all() {
    BufferNamePool pool;
    pool.release(10u, TARGET_ARRAY, USAGE_STREAM, 128u);
    pool.release(20u, TARGET_ARRAY, USAGE_STREAM, 128u);
    pool.release(30u, TARGET_ELEMENT, USAGE_STREAM, 64u);

    g_deleted.clear();
    pool.drainAll(mockDeleteBuffers);

    assert(pool.totalPooled() == 0);
    assert(pool.totalBytes() == 0);
    assert(g_deleted.size() == 3);

    bool found10 = false, found20 = false, found30 = false;
    for (uint32_t n : g_deleted) {
        if (n == 10u) found10 = true;
        if (n == 20u) found20 = true;
        if (n == 30u) found30 = true;
    }
    assert(found10 && found20 && found30);
    printf("PASS: test_drain_all\n");
}

static void test_stats_counters() {
    BufferNamePool pool;

    pool.acquire(TARGET_ARRAY, USAGE_STREAM, 64u);
    assert(pool.stats().misses == 1);
    assert(pool.stats().hits == 0);

    pool.release(5u, TARGET_ARRAY, USAGE_STREAM, 64u);
    assert(pool.stats().deleteSaved == 1);

    pool.acquire(TARGET_ARRAY, USAGE_STREAM, 64u);
    assert(pool.stats().hits == 1);
    assert(pool.stats().genSaved == 1);

    for (uint32_t i = 1; i <= 32; ++i)
        pool.release(i, TARGET_ARRAY, USAGE_STREAM, 128u);

    const uint64_t evictionsBefore = pool.stats().evictions;
    pool.release(99u, TARGET_ARRAY, USAGE_STREAM, 128u);
    assert(pool.stats().evictions == evictionsBefore + 1);

    pool.resetStats();
    assert(pool.stats().hits == 0);
    assert(pool.stats().misses == 0);
    assert(pool.stats().evictions == 0);
    printf("PASS: test_stats_counters\n");
}

static void test_side_map() {
    BufferNamePool pool;

    assert(pool.lookupSideMap(99u) == nullptr);
    assert(pool.lookupBucket(99u) == 0u);

    pool.registerName(42u, TARGET_ARRAY, USAGE_STREAM, 256u);
    const BufferNamePool::SideMapEntry* entry = pool.lookupSideMap(42u);
    assert(entry != nullptr);
    assert(entry->target == TARGET_ARRAY);
    assert(entry->usageType == USAGE_STREAM);
    assert(entry->capacityBucket == 256u);
    assert(pool.lookupBucket(42u) == 256u);

    pool.unregisterName(42u);
    assert(pool.lookupSideMap(42u) == nullptr);
    assert(pool.lookupBucket(42u) == 0u);
    printf("PASS: test_side_map\n");
}

static void test_eviction_on_full() {
    BufferNamePool pool;
    g_deleted.clear();

    for (uint32_t i = 1; i <= 32; ++i)
        assert(pool.release(i, TARGET_ARRAY, USAGE_STREAM, 128));

    assert(pool.releaseWithEvict(100u, TARGET_ARRAY, USAGE_STREAM, 128, mockDeleteBuffers));
    assert(pool.totalPooled() == 32);
    assert(g_deleted.size() == 1);
    assert(g_deleted[0] == 1u);

    assert(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128) == 100u);
    printf("PASS: test_eviction_on_full\n");
}

int main() {
    test_acquire_miss();
    test_release_acquire_roundtrip();
    test_per_bucket_overflow();
    test_global_overflow();
    test_bytes_budget_overflow();
    test_drain_all();
    test_stats_counters();
    test_side_map();
    test_eviction_on_full();
    printf("All tests passed!\n");
    return 0;
}
