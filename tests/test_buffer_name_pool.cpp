#include "BufferNamePool.hpp"

#include <doctest/doctest.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <new>
#include <vector>

// Tracks LIVE global allocations (new minus delete) so a test can prove the pool's
// bookkeeping does not grow with release/acquire churn. Counting live rather than
// total calls keeps the FIFO design's paired insert/erase allocations out of the
// measurement while still catching per-cycle growth (the old deque leak kept every
// record: +200k live allocations over the same loop). Atomic so a future worker
// thread cannot turn the counter into a data race; the measured windows themselves
// are single-threaded. Over-aligned allocation forms are not replaced because
// nothing here requests over-aligned storage.
static std::atomic<long long> g_liveAllocs{0};

void* operator new(std::size_t n) {
    g_liveAllocs.fetch_add(1, std::memory_order_relaxed);
    if (void* p = std::malloc(n != 0 ? n : 1))
        return p;
    throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return ::operator new(n); }
void* operator new(std::size_t n, const std::nothrow_t&) noexcept {
    try {
        return ::operator new(n);
    } catch (...) {
        return nullptr;
    }
}
void* operator new[](std::size_t n, const std::nothrow_t& t) noexcept {
    return ::operator new(n, t);
}
void operator delete(void* p) noexcept {
    if (p)
        g_liveAllocs.fetch_sub(1, std::memory_order_relaxed);
    std::free(p);
}
void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete(void* p, std::size_t) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t) noexcept { ::operator delete(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { ::operator delete(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { ::operator delete(p); }

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

// Steady-state churn (one stream VB created and destroyed per iteration) must not
// grow any internal bookkeeping. The old eviction design kept a global FIFO of
// released names that was only drained while evicting, so every cycle leaked one
// live record; each pooled name now owns exactly one record, erased on reuse.
TEST_CASE("test_buffer_name_pool/churn_does_not_grow_bookkeeping") {
    BufferNamePool pool;

    // Warm up so the bucket vector already has its steady-state capacity.
    REQUIRE(pool.release(7u, TARGET_ARRAY, USAGE_STREAM, kBucket128));
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128), 7u);

    const long long before = g_liveAllocs.load(std::memory_order_relaxed);
    bool steady = true;
    for (int i = 0; i < 200000 && steady; ++i) {
        steady = pool.release(7u, TARGET_ARRAY, USAGE_STREAM, kBucket128) &&
                 pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128) == 7u;
    }
    const long long delta = g_liveAllocs.load(std::memory_order_relaxed) - before;

    REQUIRE(steady);
    // 0 expected; the slack only absorbs container internals. Per-cycle growth is
    // far above it: the old deque leak adds 200k live allocations to this loop.
    INFO("live allocations during 200000 release/acquire cycles: " << delta);
    REQUIRE_LE(delta, 16);
    REQUIRE_EQ(pool.totalPooled(), 0u);
    REQUIRE_EQ(pool.totalBytes(), 0u);
    REQUIRE_EQ(pool.totalQueued(), 0u);
}

// A single eviction is not always enough: a 4MB bucket arriving at a pool holding
// (cap - 4MB) must free as many names as the budget needs, oldest first. The old
// code evicted once and then admitted the new name, leaving the pool over
// MAX_TOTAL_BYTES.
TEST_CASE("test_buffer_name_pool/byte_budget_evicts_until_the_new_name_fits") {
    BufferNamePool pool;
    g_deleted.clear();

    const uint32_t oneMB  = 1024u * 1024u;
    const uint32_t fourMB = 4u * 1024u * 1024u;
    const uint32_t need   = fourMB / oneMB;      // evictions a 4MB bucket forces
    const size_t   fill   = kBytesCap / oneMB;   // stay exactly at the byte cap
    REQUIRE_GT(fill, need);

    for (size_t i = 0; i < fill; ++i) {
        const uint32_t name  = static_cast<uint32_t>(i) + 1u;
        const uint32_t usage = USAGE_STREAM + static_cast<uint32_t>(i);
        REQUIRE(pool.release(name, TARGET_ARRAY, usage, oneMB));
        // Production keeps sideMap and the idle pool disjoint, but an eviction
        // must never leave a stale entry behind either way: a pooled name that
        // is still in sideMap would leak one map node per eviction.
        pool.registerName(name, TARGET_ARRAY, usage, oneMB);
    }
    REQUIRE_EQ(pool.totalBytes(), fill * oneMB);
    REQUIRE_EQ(pool.totalQueued(), pool.totalPooled());

    REQUIRE(pool.releaseWithEvict(999u, TARGET_ARRAY, USAGE_STREAM + fill, fourMB,
                                  mockDeleteBuffers));

    // Global FIFO order: the four oldest names pay, in release order.
    REQUIRE_EQ(g_deleted.size(), static_cast<size_t>(need));
    for (uint32_t i = 0; i < need; ++i)
        REQUIRE_EQ(g_deleted[i], i + 1u);
    REQUIRE_EQ(pool.totalBytes(), (fill - need) * oneMB + fourMB);
    REQUIRE_LE(pool.totalBytes(), kBytesCap);
    for (uint32_t n : g_deleted)
        REQUIRE_EQ(pool.lookupSideMap(n), nullptr);
    // Idle names are not supposed to be in sideMap; the incoming one never is.
    REQUIRE_EQ(pool.lookupSideMap(999u), nullptr);
    REQUIRE_EQ(pool.totalQueued(), pool.totalPooled());
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM + fill, fourMB), 999u);
}

// Both eviction paths must drop the evicted name's FIFO record and sideMap entry;
// a leftover in either one grows without bound.
TEST_CASE("test_buffer_name_pool/eviction_drops_fifo_and_side_map_entries") {
    BufferNamePool pool;
    g_deleted.clear();

    for (uint32_t i = 1; i <= kPerBucketCap; ++i) {
        REQUIRE(pool.release(i, TARGET_ARRAY, USAGE_STREAM, kBucket128));
        pool.registerName(i, TARGET_ARRAY, USAGE_STREAM, kBucket128);
    }
    REQUIRE_EQ(pool.totalQueued(), pool.totalPooled());

    // Per-bucket path: the bucket is full, so its oldest name is evicted.
    REQUIRE(pool.releaseWithEvict(1000u, TARGET_ARRAY, USAGE_STREAM, kBucket128,
                                  mockDeleteBuffers));
    REQUIRE_EQ(g_deleted.size(), 1u);
    REQUIRE_EQ(g_deleted[0], 1u);
    REQUIRE_EQ(pool.lookupSideMap(1u), nullptr);
    REQUIRE_EQ(pool.totalQueued(), pool.totalPooled());
}

// Above 2^31 the round-up used to wrap v++ to 0 and file the buffer under the
// 64-byte bucket, which let a multi-GB name pass the byte budget and be reused by
// an 8-byte request. Exactly 2^31 never wrapped; only larger sizes did.
TEST_CASE("test_buffer_name_pool/oversized_size_does_not_wrap_into_the_smallest_bucket") {
    BufferNamePool pool;
    g_deleted.clear();

    REQUIRE_EQ(BufferNamePool::bucketOf(0x80000000u), 0x80000000u);
    REQUIRE_EQ(BufferNamePool::bucketOf(0x80000001u), 0x80000000u);
    REQUIRE_EQ(BufferNamePool::bucketOf(0xFFFFFFFFu), 0x80000000u);

    // The refusal below presumes the byte budget stays below 2GB.
    REQUIRE_LT(kBytesCap, size_t{1} << 31);

    // An idle pool must not be flushed for a bucket that can never fit: the
    // refusal must leave existing names banked and delete nothing itself.
    REQUIRE(pool.release(5u, TARGET_ARRAY, USAGE_STREAM, kBucket128));
    REQUIRE_EQ(pool.totalQueued(), 1u);
    REQUIRE_FALSE(pool.releaseWithEvict(9u, TARGET_ARRAY, USAGE_STREAM + 1u, 0x80000001u,
                                        mockDeleteBuffers));
    REQUIRE(g_deleted.empty());
    REQUIRE_EQ(pool.totalBytes(), kBucket128);
    REQUIRE_EQ(pool.totalPooled(), 1u);
    REQUIRE_EQ(pool.totalQueued(), 1u);
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128), 5u);
    REQUIRE_EQ(pool.totalQueued(), 0u);

    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM + 1u, 0x80000001u), 0u);
}

// ---- Regression cases from issue #54 (BB-GOAT): the FIFO queue must be bounded
// by the pool itself, and every reuse must refresh global eviction order. ----

TEST_CASE("test_buffer_name_pool/repeated_reuse_keeps_fifo_bounded") {
    BufferNamePool pool;
    for (size_t i = 0; i < 1000000; ++i) {
        REQUIRE(pool.release(42u, TARGET_ARRAY, USAGE_STREAM, 128u));
        REQUIRE_EQ(pool.totalQueued(), 1u);
        REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128u), 42u);
        REQUIRE_EQ(pool.totalQueued(), 0u);
    }
    REQUIRE_EQ(pool.totalPooled(), 0u);
    REQUIRE_EQ(pool.totalBytes(), 0u);
}

TEST_CASE("test_buffer_name_pool/bucket_evictions_keep_fifo_bounded") {
    BufferNamePool pool;
    g_deleted.clear();
    const uint32_t releases = static_cast<uint32_t>(kPerBucketCap * 100);
    for (uint32_t name = 1; name <= releases; ++name) {
        REQUIRE(pool.releaseWithEvict(name, TARGET_ARRAY, USAGE_STREAM, kBucket128,
                                      mockDeleteBuffers));
        REQUIRE_EQ(pool.totalQueued(), pool.totalPooled());
        REQUIRE_LE(pool.totalQueued(), kPerBucketCap);
    }
    // Oldest-first: 1..releases-kPerBucketCap were evicted in order.
    REQUIRE_EQ(g_deleted.size(), releases - kPerBucketCap);
    pool.drainAll(mockDeleteBuffers);
    REQUIRE_EQ(pool.totalQueued(), 0u);
    REQUIRE_EQ(g_deleted.size(), releases);
    std::sort(g_deleted.begin(), g_deleted.end());
    for (uint32_t name = 1; name <= releases; ++name)
        REQUIRE_EQ(g_deleted[name - 1], name);
    REQUIRE(pool.release(42u, TARGET_ARRAY, USAGE_STREAM, kBucket128));
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, kBucket128), 42u);
    REQUIRE_EQ(pool.totalQueued(), 0u);
}

TEST_CASE("test_buffer_name_pool/large_buffer_evicts_until_within_budget") {
    BufferNamePool pool;
    g_deleted.clear();
    const uint32_t oneMB = 1024u * 1024u;
    const uint32_t smallCount = static_cast<uint32_t>(kBytesCap / oneMB);
    for (uint32_t name = 1; name <= smallCount; ++name)
        REQUIRE(pool.release(name, TARGET_ARRAY, USAGE_STREAM, oneMB));
    REQUIRE(pool.releaseWithEvict(1000u, TARGET_ELEMENT, USAGE_STREAM, 8u * oneMB,
                                  mockDeleteBuffers));
    REQUIRE_EQ(g_deleted.size(), 8u);
    for (uint32_t i = 0; i < 8; ++i)
        REQUIRE_EQ(g_deleted[i], i + 1);
    REQUIRE_EQ(pool.totalBytes(), kBytesCap);
    REQUIRE_EQ(pool.totalQueued(), pool.totalPooled());
    REQUIRE_EQ(pool.acquire(TARGET_ELEMENT, USAGE_STREAM, 8u * oneMB), 1000u);
    pool.drainAll(mockDeleteBuffers);
    REQUIRE_EQ(pool.totalQueued(), 0u);
}

TEST_CASE("test_buffer_name_pool/oversized_buffer_does_not_evict_existing_names") {
    BufferNamePool pool;
    g_deleted.clear();
    REQUIRE(pool.release(42u, TARGET_ARRAY, USAGE_STREAM, 128u));
    for (const uint32_t size : {static_cast<uint32_t>(kBytesCap + 1), 0xffffffffu}) {
        REQUIRE_FALSE(
            pool.releaseWithEvict(99u, TARGET_ARRAY, USAGE_STREAM, size, mockDeleteBuffers));
        REQUIRE_EQ(pool.totalPooled(), 1u);
        REQUIRE_EQ(pool.totalBytes(), 128u);
        REQUIRE_EQ(pool.totalQueued(), 1u);
        REQUIRE(g_deleted.empty());
    }
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128u), 42u);
}

TEST_CASE("test_buffer_name_pool/reuse_refreshes_global_eviction_order") {
    BufferNamePool pool;
    g_deleted.clear();
    // Two half-budget buffers fill the pool; reusing the first makes it the newest.
    const uint32_t halfBudget = static_cast<uint32_t>(kBytesCap / 2);
    REQUIRE(pool.release(1u, TARGET_ARRAY, USAGE_STREAM, halfBudget));
    REQUIRE(pool.release(2u, TARGET_ELEMENT, USAGE_STREAM, halfBudget));
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, halfBudget), 1u);
    REQUIRE(pool.release(1u, TARGET_ARRAY, USAGE_STREAM, halfBudget));
    REQUIRE(pool.releaseWithEvict(3u, TARGET_ARRAY, USAGE_STREAM, 128u, mockDeleteBuffers));
    REQUIRE_EQ(g_deleted.size(), 1u);
    REQUIRE_EQ(g_deleted[0], 2u);
    REQUIRE_EQ(pool.totalQueued(), 2u);
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, halfBudget), 1u);
    REQUIRE_EQ(pool.acquire(TARGET_ARRAY, USAGE_STREAM, 128u), 3u);
    REQUIRE_EQ(pool.totalQueued(), 0u);
}
