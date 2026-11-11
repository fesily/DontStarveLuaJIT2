#include "BufferNamePool.hpp"

#include <cstdio>
#include <vector>
#include "support/test_assert.hpp"

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
    DS_REQUIRE(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128) == 0);
    DS_REQUIRE(pool.stats().misses == 1);
    DS_REQUIRE(pool.stats().hits == 0);
    printf("PASS: test_acquire_miss\n");
}

static void test_release_acquire_roundtrip() {
    BufferNamePool pool;
    DS_REQUIRE(pool.release(42u, TARGET_ARRAY, USAGE_STREAM, 128));
    DS_REQUIRE(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128) == 42u);
    DS_REQUIRE(pool.stats().hits == 1);
    DS_REQUIRE(pool.stats().deleteSaved == 1);
    DS_REQUIRE(pool.stats().genSaved == 1);
    printf("PASS: test_release_acquire_roundtrip\n");
}

static void test_per_bucket_overflow() {
    BufferNamePool pool;
    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        DS_REQUIRE(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));

    // Bucket at cap: release() (no delete callback) must refuse and count it.
    DS_REQUIRE(!pool.release(static_cast<uint32_t>(kPerBucketCap) + 1u, TARGET_ARRAY, USAGE_STREAM,
                         kBucket128));
    DS_REQUIRE(pool.totalPooled() == kPerBucketCap);
    DS_REQUIRE(pool.stats().evictions >= 1);
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
            DS_REQUIRE(pool.release(name, TARGET_ARRAY, usage, 128u));
    }
    DS_REQUIRE(released == kTotalCap);
    DS_REQUIRE(pool.totalPooled() == kTotalCap);

    // Fresh, empty bucket: the total cap (not the per-bucket cap) must refuse.
    DS_REQUIRE(!pool.release(name, TARGET_ARRAY, USAGE_STREAM + static_cast<uint32_t>(buckets), 128u));
    printf("PASS: test_global_overflow\n");
}

static void test_bytes_budget_overflow() {
    BufferNamePool pool;
    const uint32_t oneMB = 1024u * 1024u;
    const size_t needed = static_cast<size_t>(kBytesCap / oneMB);
    DS_REQUIRE(needed > 0 && needed <= kTotalCap);

    uint32_t name = 1;
    size_t released = 0;
    size_t buckets = 0;
    while (released < needed) {
        const uint32_t usage = USAGE_STREAM + static_cast<uint32_t>(buckets++);
        for (size_t i = 0; i < kPerBucketCap && released < needed; ++i, ++name, ++released)
            DS_REQUIRE(pool.release(name, TARGET_ARRAY, usage, oneMB));
    }
    DS_REQUIRE(pool.totalBytes() == static_cast<size_t>(needed) * oneMB);

    // Fresh, empty bucket: the byte budget (not the bucket/total caps) must refuse.
    DS_REQUIRE(!pool.release(name, TARGET_ARRAY, USAGE_STREAM + static_cast<uint32_t>(buckets), oneMB));
    printf("PASS: test_bytes_budget_overflow\n");
}

static void test_drain_all() {
    BufferNamePool pool;
    pool.release(10u, TARGET_ARRAY, USAGE_STREAM, 128u);
    pool.release(20u, TARGET_ARRAY, USAGE_STREAM, 128u);
    pool.release(30u, TARGET_ELEMENT, USAGE_STREAM, 64u);

    g_deleted.clear();
    pool.drainAll(mockDeleteBuffers);

    DS_REQUIRE(pool.totalPooled() == 0);
    DS_REQUIRE(pool.totalBytes() == 0);
    DS_REQUIRE(g_deleted.size() == 3);

    bool found10 = false, found20 = false, found30 = false;
    for (uint32_t n : g_deleted) {
        if (n == 10u) found10 = true;
        if (n == 20u) found20 = true;
        if (n == 30u) found30 = true;
    }
    DS_REQUIRE(found10 && found20 && found30);
    printf("PASS: test_drain_all\n");
}

static void test_stats_counters() {
    BufferNamePool pool;

    pool.acquire(TARGET_ARRAY, USAGE_STREAM, 64u);
    DS_REQUIRE(pool.stats().misses == 1);
    DS_REQUIRE(pool.stats().hits == 0);

    pool.release(5u, TARGET_ARRAY, USAGE_STREAM, 64u);
    DS_REQUIRE(pool.stats().deleteSaved == 1);

    pool.acquire(TARGET_ARRAY, USAGE_STREAM, 64u);
    DS_REQUIRE(pool.stats().hits == 1);
    DS_REQUIRE(pool.stats().genSaved == 1);

    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128);

    const uint64_t evictionsBefore = pool.stats().evictions;
    pool.release(static_cast<uint32_t>(kPerBucketCap) + 99u, TARGET_ARRAY, USAGE_STREAM, kBucket128);
    DS_REQUIRE(pool.stats().evictions == evictionsBefore + 1);

    pool.resetStats();
    DS_REQUIRE(pool.stats().hits == 0);
    DS_REQUIRE(pool.stats().misses == 0);
    DS_REQUIRE(pool.stats().evictions == 0);
    printf("PASS: test_stats_counters\n");
}

static void test_side_map() {
    BufferNamePool pool;

    DS_REQUIRE(pool.lookupSideMap(99u) == nullptr);
    DS_REQUIRE(pool.lookupBucket(99u) == 0u);

    pool.registerName(42u, TARGET_ARRAY, USAGE_STREAM, 256u);
    const BufferNamePool::SideMapEntry* entry = pool.lookupSideMap(42u);
    DS_REQUIRE(entry != nullptr);
    DS_REQUIRE(entry->target == TARGET_ARRAY);
    DS_REQUIRE(entry->usageType == USAGE_STREAM);
    DS_REQUIRE(entry->capacityBucket == 256u);
    DS_REQUIRE(pool.lookupBucket(42u) == 256u);

    pool.unregisterName(42u);
    DS_REQUIRE(pool.lookupSideMap(42u) == nullptr);
    DS_REQUIRE(pool.lookupBucket(42u) == 0u);
    printf("PASS: test_side_map\n");
}

static void test_eviction_on_full() {
    BufferNamePool pool;
    g_deleted.clear();

    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        DS_REQUIRE(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));

    // Bucket full: releaseWithEvict frees the oldest entry and admits the new name.
    const uint32_t fresh = static_cast<uint32_t>(kPerBucketCap) + 100u;
    DS_REQUIRE(pool.releaseWithEvict(fresh, TARGET_ARRAY, USAGE_STREAM, kBucket128, mockDeleteBuffers));
    DS_REQUIRE(pool.totalPooled() == kPerBucketCap);
    DS_REQUIRE(g_deleted.size() == 1);
    DS_REQUIRE(g_deleted[0] == 1u);

    DS_REQUIRE(pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128) == fresh);
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
