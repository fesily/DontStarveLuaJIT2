#include "BufferNamePool.hpp"

#include <doctest/doctest.h>

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

TEST_CASE("test_buffer_name_pool/acquire_miss") {
    BufferNamePool pool;
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128), 0);
    REQUIRE_EQ(pool.stats().misses, 1);
    REQUIRE_EQ(pool.stats().hits, 0);
}

TEST_CASE("test_buffer_name_pool/release_acquire_roundtrip") {
    BufferNamePool pool;
    REQUIRE(pool.release(42u, TARGET_ARRAY, USAGE_STREAM, 128));
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128), 42u);
    REQUIRE_EQ(pool.stats().hits, 1);
    REQUIRE_EQ(pool.stats().deleteSaved, 1);
    REQUIRE_EQ(pool.stats().genSaved, 1);
}

TEST_CASE("test_buffer_name_pool/per_bucket_overflow") {
    BufferNamePool pool;
    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        REQUIRE(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));

    // Bucket at cap: release() (no delete callback) must refuse and count it.
    REQUIRE_FALSE(pool.release(static_cast<uint32_t>(kPerBucketCap) + 1u, TARGET_ARRAY, USAGE_STREAM,
                         kBucket128));
    REQUIRE_EQ(pool.totalPooled(), kPerBucketCap);
    REQUIRE_GE(pool.stats().evictions, 1);
}

TEST_CASE("test_buffer_name_pool/global_overflow") {
    BufferNamePool pool;
    // Distinct usage values keep every (target, usage, bucket) group under the
    // per-bucket cap while the total cap fills up.
    const size_t buckets = (kTotalCap + kPerBucketCap - 1) / kPerBucketCap;
    uint32_t name = 1;
    size_t released = 0;
    for (size_t b = 0; b < buckets && released < kTotalCap; ++b) {
        const uint32_t usage = USAGE_STREAM + static_cast<uint32_t>(b);
        for (size_t i = 0; i < kPerBucketCap && released < kTotalCap; ++i, ++name, ++released)
            REQUIRE(pool.release(name, TARGET_ARRAY, usage, 128u));
    }
    REQUIRE_EQ(released, kTotalCap);
    REQUIRE_EQ(pool.totalPooled(), kTotalCap);

    // Fresh, empty bucket: the total cap (not the per-bucket cap) must refuse.
    REQUIRE_FALSE(pool.release(name, TARGET_ARRAY, USAGE_STREAM + static_cast<uint32_t>(buckets), 128u));
}

TEST_CASE("test_buffer_name_pool/bytes_budget_overflow") {
    BufferNamePool pool;
    const uint32_t oneMB = 1024u * 1024u;
    const size_t needed = static_cast<size_t>(kBytesCap / oneMB);
    REQUIRE_GT(needed, 0);
    REQUIRE_LE(needed, kTotalCap);

    uint32_t name = 1;
    size_t released = 0;
    size_t buckets = 0;
    while (released < needed) {
        const uint32_t usage = USAGE_STREAM + static_cast<uint32_t>(buckets++);
        for (size_t i = 0; i < kPerBucketCap && released < needed; ++i, ++name, ++released)
            REQUIRE(pool.release(name, TARGET_ARRAY, usage, oneMB));
    }
    REQUIRE(pool.totalBytes() == static_cast<size_t>(needed) * oneMB);

    // Fresh, empty bucket: the byte budget (not the bucket/total caps) must refuse.
    REQUIRE_FALSE(pool.release(name, TARGET_ARRAY, USAGE_STREAM + static_cast<uint32_t>(buckets), oneMB));
}

TEST_CASE("test_buffer_name_pool/drain_all") {
    BufferNamePool pool;
    pool.release(10u, TARGET_ARRAY, USAGE_STREAM, 128u);
    pool.release(20u, TARGET_ARRAY, USAGE_STREAM, 128u);
    pool.release(30u, TARGET_ELEMENT, USAGE_STREAM, 64u);

    g_deleted.clear();
    pool.drainAll(mockDeleteBuffers);

    REQUIRE_EQ(pool.totalPooled(), 0);
    REQUIRE_EQ(pool.totalBytes(), 0);
    REQUIRE_EQ(g_deleted.size(), 3);

    bool found10 = false, found20 = false, found30 = false;
    for (uint32_t n : g_deleted) {
        if (n == 10u) found10 = true;
        if (n == 20u) found20 = true;
        if (n == 30u) found30 = true;
    }
    REQUIRE(found10);
    REQUIRE(found20);
    REQUIRE(found30);
}

TEST_CASE("test_buffer_name_pool/stats_counters") {
    BufferNamePool pool;

    pool.acquire(TARGET_ARRAY, USAGE_STREAM, 64u);
    REQUIRE_EQ(pool.stats().misses, 1);
    REQUIRE_EQ(pool.stats().hits, 0);

    pool.release(5u, TARGET_ARRAY, USAGE_STREAM, 64u);
    REQUIRE_EQ(pool.stats().deleteSaved, 1);

    pool.acquire(TARGET_ARRAY, USAGE_STREAM, 64u);
    REQUIRE_EQ(pool.stats().hits, 1);
    REQUIRE_EQ(pool.stats().genSaved, 1);

    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128);

    const uint64_t evictionsBefore = pool.stats().evictions;
    pool.release(static_cast<uint32_t>(kPerBucketCap) + 99u, TARGET_ARRAY, USAGE_STREAM, kBucket128);
    REQUIRE_EQ(pool.stats().evictions, evictionsBefore + 1);

    pool.resetStats();
    REQUIRE_EQ(pool.stats().hits, 0);
    REQUIRE_EQ(pool.stats().misses, 0);
    REQUIRE_EQ(pool.stats().evictions, 0);
}

TEST_CASE("test_buffer_name_pool/side_map") {
    BufferNamePool pool;

    REQUIRE_EQ(pool.lookupSideMap(99u), nullptr);
    REQUIRE_EQ(pool.lookupBucket(99u), 0u);

    pool.registerName(42u, TARGET_ARRAY, USAGE_STREAM, 256u);
    const BufferNamePool::SideMapEntry* entry = pool.lookupSideMap(42u);
    REQUIRE_NE(entry, nullptr);
    REQUIRE(entry->target == TARGET_ARRAY);
    REQUIRE(entry->usageType == USAGE_STREAM);
    REQUIRE(entry->capacityBucket == 256u);
    REQUIRE_EQ(pool.lookupBucket(42u), 256u);

    pool.unregisterName(42u);
    REQUIRE_EQ(pool.lookupSideMap(42u), nullptr);
    REQUIRE_EQ(pool.lookupBucket(42u), 0u);
}

TEST_CASE("test_buffer_name_pool/eviction_on_full") {
    BufferNamePool pool;
    g_deleted.clear();

    for (uint32_t i = 1; i <= kPerBucketCap; ++i)
        REQUIRE(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));

    // Bucket full: releaseWithEvict frees the oldest entry and admits the new name.
    const uint32_t fresh = static_cast<uint32_t>(kPerBucketCap) + 100u;
    REQUIRE(pool.releaseWithEvict(fresh, TARGET_ARRAY, USAGE_STREAM, kBucket128, mockDeleteBuffers));
    REQUIRE_EQ(pool.totalPooled(), kPerBucketCap);
    REQUIRE_EQ(g_deleted.size(), 1);
    REQUIRE_EQ(g_deleted[0], 1u);

    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128), fresh);
}
