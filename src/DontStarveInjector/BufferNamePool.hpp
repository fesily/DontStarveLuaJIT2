#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <unordered_map>
#include <vector>

struct BufferPoolKey {
    uint32_t target;         // GL_ARRAY_BUFFER (0x8892) / GL_ELEMENT_ARRAY_BUFFER (0x8893)
    uint32_t usageType;      // eUsageType raw value (STREAM_DRAW=10, etc.)
    uint32_t capacityBucket; // roundUpPow2(byteSize), minimum 64

    bool operator==(const BufferPoolKey& o) const noexcept {
        return target == o.target && usageType == o.usageType &&
               capacityBucket == o.capacityBucket;
    }
};

struct BufferPoolKeyHash {
    size_t operator()(const BufferPoolKey& k) const noexcept {
        size_t h = std::hash<uint32_t>{}(k.target);
        h ^= std::hash<uint32_t>{}(k.usageType) + 0x9e3779b9u + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(k.capacityBucket) + 0x9e3779b9u + (h << 6) + (h >> 2);
        return h;
    }
};

class BufferNamePool {
public:
    static constexpr size_t MAX_POOL_SIZE_PER_BUCKET = 128;
    static constexpr size_t MAX_TOTAL_POOLED         = 1024;
    static constexpr size_t MAX_TOTAL_BYTES          = 64u * 1024u * 1024u;

    uint32_t acquire(uint32_t target, uint32_t usageType, uint32_t byteSize) {
        const auto key = makeKey(target, usageType, byteSize);
        auto it = pool_.find(key);
        if (it != pool_.end() && !it->second.empty()) {
            const uint32_t name = it->second.back();
            it->second.pop_back();
            totalPooled_--;
            totalBytes_ -= key.capacityBucket;
            stats_.hits++;
            stats_.reusedBytes += key.capacityBucket;
            stats_.genSaved++;
            return name;
        }
        stats_.misses++;
        return 0;
    }

    // Returns false if any capacity limit is exceeded; caller must then call glDeleteBuffers.
    bool release(uint32_t name, uint32_t target, uint32_t usageType, uint32_t byteSize) {
        return releaseWithEvict(name, target, usageType, byteSize, nullptr);
    }

    // Release with eviction: if pool is full, evict oldest name from the largest bucket
    // and call deleteBuffers on it, making room for the new name.
    // Returns false only if eviction is impossible (empty pool edge case).
    bool releaseWithEvict(uint32_t name, uint32_t target, uint32_t usageType,
                          uint32_t byteSize,
                          void (*deleteBuffers)(uint32_t, const uint32_t*)) {
        const auto key = makeKey(target, usageType, byteSize);
        auto& bucket = pool_[key];

        if (bucket.size() >= MAX_POOL_SIZE_PER_BUCKET) {
            if (!deleteBuffers) {
                stats_.evictions++;
                return false;
            }
            uint32_t evicted = bucket.front();
            bucket.erase(bucket.begin());
            totalPooled_--;
            totalBytes_ -= key.capacityBucket;
            deleteBuffers(1, &evicted);
            sideMap_.erase(evicted);
            stats_.evictions++;
        } else if (totalPooled_ >= MAX_TOTAL_POOLED ||
                   totalBytes_ + key.capacityBucket > MAX_TOTAL_BYTES) {
            if (!deleteBuffers) {
                stats_.evictions++;
                return false;
            }
            if (!evictOldest(deleteBuffers)) {
                stats_.evictions++;
                return false;
            }
        }

        bucket.push_back(name);
        totalPooled_++;
        totalBytes_ += key.capacityBucket;
        globalFifo_.push_back({key, name});
        stats_.deleteSaved++;
        return true;
    }

    void drainAll(void (*deleteBuffers)(uint32_t, const uint32_t*)) {
        for (auto& [key, bucket] : pool_) {
            if (!bucket.empty()) {
                deleteBuffers(static_cast<uint32_t>(bucket.size()), bucket.data());
            }
        }
        pool_.clear();
        totalPooled_ = 0;
        totalBytes_  = 0;
        sideMap_.clear();
        globalFifo_.clear();
    }

    struct SideMapEntry {
        uint32_t target;
        uint32_t usageType;
        uint32_t capacityBucket;
    };

    void registerName(uint32_t name, uint32_t target, uint32_t usageType,
                      uint32_t capacityBucket) {
        sideMap_[name] = SideMapEntry{target, usageType, capacityBucket};
    }

    void unregisterName(uint32_t name) { sideMap_.erase(name); }

    const SideMapEntry* lookupSideMap(uint32_t name) const {
        const auto it = sideMap_.find(name);
        return (it == sideMap_.end()) ? nullptr : &it->second;
    }

    uint32_t lookupBucket(uint32_t name) const {
        const auto it = sideMap_.find(name);
        return (it == sideMap_.end()) ? 0u : it->second.capacityBucket;
    }

    struct Stats {
        uint64_t hits        = 0; // acquire() cache hits
        uint64_t misses      = 0; // acquire() cache misses
        uint64_t evictions   = 0; // release() rejected due to capacity limits
        uint64_t reusedBytes = 0; // bytes served from pool (sum of bucket sizes on hit)
        uint64_t genSaved    = 0; // glGenBuffers calls avoided
        uint64_t deleteSaved = 0; // glDeleteBuffers calls avoided
    };

    const Stats& stats() const noexcept { return stats_; }
    void         resetStats() noexcept { stats_ = Stats{}; }

    size_t totalPooled() const noexcept { return totalPooled_; }
    size_t totalBytes()  const noexcept { return totalBytes_; }

private:
    bool evictOldest(void (*deleteBuffers)(uint32_t, const uint32_t*)) {
        while (!globalFifo_.empty()) {
            auto [key, name] = globalFifo_.front();
            globalFifo_.pop_front();

            auto it = pool_.find(key);
            if (it == pool_.end() || it->second.empty())
                continue;

            auto& bucket = it->second;
            auto nameIt = std::find(bucket.begin(), bucket.end(), name);
            if (nameIt == bucket.end())
                continue;

            bucket.erase(nameIt);
            totalPooled_--;
            totalBytes_ -= key.capacityBucket;
            deleteBuffers(1, &name);
            sideMap_.erase(name);
            stats_.evictions++;
            return true;
        }
        return false;
    }

    static uint32_t roundUpPow2(uint32_t v) noexcept {
        if (v == 0) return 64u;
        v--;
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        v++;
        return v < 64u ? 64u : v;
    }

    static BufferPoolKey makeKey(uint32_t target, uint32_t usageType,
                                 uint32_t byteSize) noexcept {
        return {target, usageType, roundUpPow2(byteSize)};
    }

    std::unordered_map<BufferPoolKey, std::vector<uint32_t>, BufferPoolKeyHash> pool_;
    std::unordered_map<uint32_t, SideMapEntry> sideMap_;
    std::deque<std::pair<BufferPoolKey, uint32_t>> globalFifo_;

    size_t totalPooled_ = 0;
    size_t totalBytes_  = 0;
    Stats  stats_;
};
