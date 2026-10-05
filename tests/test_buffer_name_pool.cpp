#include "BufferNamePool.hpp"

#include <cassert>
#include <cstdio>
#include <vector>

static constexpr uint32_t TARGET_ARRAY   = 0x8892u;
static constexpr uint32_t TARGET_ELEMENT = 0x8893u;
static constexpr uint32_t USAGE_STREAM   = 10u;

// Expectations are expressed through the pool's own caps so they cannot go
// stale when the caps change.
static constexpr size_t kPerBucketCap = BufferNamePool::MAX_POOL_SIZE_PER_BUCKET;
static constexpr size_t kTotalCap     = BufferNamePool::MAX_TOTAL_POOLED;
static constexpr size_t kBytesCap     = BufferNamePool::MAX_TOTAL_BYTES;
static constexpr uint32_t kBucket128  = 128u;

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
    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        assert(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));

    // Bucket at cap: release() (no delete callback) must refuse and count it.
    assert(!pool.release(static_cast<uint32_t>(kPerBucketCap) + 1u, TARGET_ARRAY, USAGE_STREAM,
                         kBucket128));
    assert(pool.totalPooled() == kPerBucketCap);
    assert(pool.stats().evictions >= 1);
    printf("PASS: test_per_bucket_overflow\n");
}

static void test_global_overflow() {
    BufferNamePool pool;
    // Distinct usage values keep every (target, usage, bucket) group under the
    // per-bucket cap while the total cap fills up.
    const size_t buckets = (kTotalCap + kPerBucketCap - 1) / kPerBucketCap;
    uint32_t name = 1;
    size_t released = 0;
    for (size_t b = 0; b < buckets && released < kTotalCap; ++b) {
        const uint32_t usage = USAGE_STREAM + static_cast<uint32_t>(b);
        for (size_t i = 0; i < kPerBucketCap && released < kTotalCap; ++i, ++name, ++released)
            assert(pool.release(name, TARGET_ARRAY, usage, 128u));
    }
    assert(released == kTotalCap);
    assert(pool.totalPooled() == kTotalCap);

    // Fresh, empty bucket: the total cap (not the per-bucket cap) must refuse.
    assert(!pool.release(name, TARGET_ARRAY, USAGE_STREAM + static_cast<uint32_t>(buckets), 128u));
    printf("PASS: test_global_overflow\n");
}

static void test_bytes_budget_overflow() {
    BufferNamePool pool;
    const uint32_t oneMB = 1024u * 1024u;
    const size_t needed = static_cast<size_t>(kBytesCap / oneMB);
    assert(needed > 0 && needed <= kTotalCap);

    uint32_t name = 1;
    size_t released = 0;
    size_t buckets = 0;
    while (released < needed) {
        const uint32_t usage = USAGE_STREAM + static_cast<uint32_t>(buckets++);
        for (size_t i = 0; i < kPerBucketCap && released < needed; ++i, ++name, ++released)
            assert(pool.release(name, TARGET_ARRAY, usage, oneMB));
    }
    assert(pool.totalBytes() == static_cast<size_t>(needed) * oneMB);

    // Fresh, empty bucket: the byte budget (not the bucket/total caps) must refuse.
    assert(!pool.release(name, TARGET_ARRAY, USAGE_STREAM + static_cast<uint32_t>(buckets), oneMB));
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

    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128);

    const uint64_t evictionsBefore = pool.stats().evictions;
    pool.release(static_cast<uint32_t>(kPerBucketCap) + 99u, TARGET_ARRAY, USAGE_STREAM, kBucket128);
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

    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        assert(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));

    // Bucket full: releaseWithEvict frees the oldest entry and admits the new name.
    const uint32_t fresh = static_cast<uint32_t>(kPerBucketCap) + 100u;
    assert(pool.releaseWithEvict(fresh, TARGET_ARRAY, USAGE_STREAM, kBucket128, mockDeleteBuffers));
    assert(pool.totalPooled() == kPerBucketCap);
    assert(g_deleted.size() == 1);
    assert(g_deleted[0] == 1u);

    assert(pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128) == fresh);
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
